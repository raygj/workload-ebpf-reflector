// Package main is the entry point for the eBPF MCP Reflector.
//
// The reflector observes identity-bearing connections at the kernel socket layer
// via eBPF, extracts metadata (5-tuple, SPIFFE ID, JWT claims, MCP tool names),
// and mirrors it to the reflector-map sidecar over gRPC.
//
// Crawl scope: reflect-only mode on a single OCP cluster (ADR-002).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	bpf "github.com/raygj/workload-ebpf-reflector/internal/ebpf"
	"github.com/raygj/workload-ebpf-reflector/internal/extract"
	"github.com/raygj/workload-ebpf-reflector/internal/forward"
	"github.com/raygj/workload-ebpf-reflector/internal/metrics"
	"github.com/raygj/workload-ebpf-reflector/internal/policy"
	"github.com/raygj/workload-ebpf-reflector/internal/stream"
)

func main() {
	sidecarAddr := flag.String("sidecar-addr", "localhost:9100", "reflector-map sidecar gRPC address")
	metricsAddr := flag.String("metrics-addr", ":9090", "HTTP listen address for /healthz and /metrics")
	nodeID := flag.String("node-id", "", "node identifier (defaults to hostname)")
	libSSLPath := flag.String("libssl", "/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"path to libssl.so for TLS plaintext capture (SSL_write/SSL_read uprobes)")
	libCryptoPath := flag.String("libcrypto", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"path to libcrypto.so for X.509 cert capture (d2i_X509 uprobe, SPIFFE extraction)")
	otelEndpoint := flag.String("otel-endpoint", "",
		"OTLP/HTTP collector endpoint for re-forwarding captured OTel signals (e.g. http://collector:4318). "+
			"Leave empty to capture without re-forwarding.")
	policyPath := flag.String("policy", "/etc/reflector/policy.rego",
		"path to Rego policy file for SPIFFE identity evaluation (walk stage). "+
			"Falls back to compiled-in default if file is absent.")
	ifaceName := flag.String("iface", "",
		"network interface for TC drop enforcement (e.g. eth0). "+
			"Auto-detected from default route if empty. Set to 'none' to disable enforcement.")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if *nodeID == "" {
		h, _ := os.Hostname()
		*nodeID = h
	}

	startTime := time.Now()

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()

	// Prometheus metrics
	metrics.RegisterReflector(prometheus.DefaultRegisterer)

	// Metrics + health endpoint
	metricsServer := &http.Server{
		Addr:    *metricsAddr,
		Handler: metrics.NewHTTPHandler("reflector", startTime),
	}
	go func() {
		logger.Info("metrics server listening", "addr", *metricsAddr)
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// Optional OTLP re-forwarder (ADR-007)
	var fwd *forward.Forwarder
	if *otelEndpoint != "" {
		fwd = forward.NewForwarder(*otelEndpoint)
		logger.Info("OTLP re-forward enabled", "endpoint", *otelEndpoint)
	}

	// gRPC stream client — connects in background, reconnects on drop.
	sc := stream.NewClient(*sidecarAddr, *nodeID, logger)
	events := make(chan *apiv1.ReflectorEvent, 512)
	go runStreamSender(ctx, sc, events, logger)

	logger.Info("starting mcp-ebpf-reflector",
		"mode", "reflect-only",
		"stage", "crawl",
		"sidecar", *sidecarAddr,
		"node_id", *nodeID,
	)

	// --- Socket-level event loop (tcp_connect, inet_csk_accept) ---
	loader := bpf.NewLoader(logger)
	if err := loader.Load(ctx); err != nil {
		logger.Error("failed to load eBPF program", "error", err)
		logger.Info("running in metrics-only mode (eBPF not available)")
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = metricsServer.Shutdown(shutdownCtx)
		return
	}
	defer func() {
		if err := loader.Close(); err != nil {
			logger.Error("closing eBPF loader", "error", err)
		}
	}()

	logger.Info("eBPF program loaded, reading events")

	var total, parsed uint64
	go func() {
		for {
			data, err := loader.Read(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("reading event", "error", err)
				continue
			}
			total++
			metrics.EBPFEventsTotal.WithLabelValues("connection").Inc()

			ev, err := extract.ParseEvent(data)
			if err != nil {
				logger.Warn("parsing event", "error", err)
				metrics.IdentityExtractionErrorsTotal.Inc()
				continue
			}
			parsed++
			metrics.ConnectionsObservedTotal.WithLabelValues("tcp").Inc()

			logger.Info("connection",
				"type", ev.Type.String(),
				"five_tuple", ev.FiveTuple(),
				"pid", ev.PID,
			)

			select {
			case events <- connectionEventToProto(ev):
			default:
				// channel full — drop rather than block the eBPF read loop
			}
		}
	}()

	// --- TLS plaintext event loop (SSL_write, SSL_read uprobes) ---
	tlsLoader := bpf.NewTLSLoader(*libSSLPath, logger)
	if err := tlsLoader.Load(ctx); err != nil {
		logger.Warn("TLS hook not loaded — OTLP/JWT/MCP capture disabled",
			"error", err,
			"libssl", *libSSLPath,
		)
	} else {
		defer func() {
			if err := tlsLoader.Close(); err != nil {
				logger.Error("closing TLS loader", "error", err)
			}
		}()
		logger.Info("TLS hook loaded, capturing SSL_write/SSL_read plaintext")

		go runTLSEventLoop(ctx, tlsLoader, fwd, events, logger)
	}

	// --- TC drop enforcement (walk stage: auto-detected iface, disable with --iface=none) ---
	var tcLoader *bpf.TCLoader
	iface := *ifaceName
	if iface == "" {
		iface = bpf.DefaultIface()
	}
	if iface != "none" {
		tcLoader = bpf.NewTCLoader(iface, logger)
		if err := tcLoader.Load(); err != nil {
			logger.Warn("TC enforcement unavailable — running in observe-only mode",
				"iface", *ifaceName, "error", err)
			tcLoader = nil
		} else {
			defer func() {
				if err := tcLoader.Close(); err != nil {
					logger.Error("closing TC loader", "error", err)
				}
			}()
		}
	}

	// --- OPA policy evaluator (walk stage: SPIFFE identity gate) ---
	pol, err := policy.New(*policyPath, logger)
	if err != nil {
		logger.Error("failed to load policy — exiting", "error", err)
		os.Exit(1)
	}

	// --- X.509 cert event loop (d2i_X509 uprobe → SPIFFE extraction) ---
	certLoader := bpf.NewCertLoader(*libCryptoPath, logger)
	if err := certLoader.Load(ctx); err != nil {
		logger.Warn("cert hook not loaded — SPIFFE extraction disabled",
			"error", err,
			"libcrypto", *libCryptoPath,
		)
	} else {
		defer func() {
			if err := certLoader.Close(); err != nil {
				logger.Error("closing cert loader", "error", err)
			}
		}()
		logger.Info("cert hook loaded, capturing d2i_X509 for SPIFFE extraction")
		go runCertEventLoop(ctx, certLoader, pol, tcLoader, events, logger)
		go runLibCryptoScanner(ctx, certLoader, logger)
	}

	<-ctx.Done()
	logger.Info("shutting down",
		"events_total", total,
		"events_parsed", parsed,
	)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = metricsServer.Shutdown(shutdownCtx)
}

// runStreamSender drains the events channel and sends to the sidecar,
// reconnecting with backoff on any error.
func runStreamSender(ctx context.Context, sc *stream.Client, events <-chan *apiv1.ReflectorEvent, logger *slog.Logger) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		if err := sc.Connect(ctx); err != nil {
			logger.Warn("sidecar connect failed, retrying", "error", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second

		_ = sc.SendResumed()

		for {
			select {
			case <-ctx.Done():
				_ = sc.Close()
				return
			case ev := <-events:
				if err := sc.Send(ev); err != nil {
					logger.Warn("stream send failed, reconnecting", "error", err)
					_ = sc.Close()
					goto reconnect
				}
				metrics.StreamEventsSentTotal.Inc()
			}
		}
	reconnect:
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// runTLSEventLoop reads TLS plaintext events from the ring buffer,
// runs identity extractors, logs findings, updates metrics, and
// optionally re-forwards OTLP bodies.
func runTLSEventLoop(ctx context.Context, tls *bpf.TLSLoader, fwd *forward.Forwarder, events chan<- *apiv1.ReflectorEvent, logger *slog.Logger) {
	logger.Info("TLS event loop started")
	for {
		data, err := tls.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("reading TLS event", "error", err)
			continue
		}
		metrics.EBPFEventsTotal.WithLabelValues("tls").Inc()

		ev, err := extract.ParseTLSDataEvent(data)
		if err != nil {
			logger.Warn("parsing TLS event", "error", err)
			metrics.IdentityExtractionErrorsTotal.Inc()
			continue
		}

		result := extract.ExtractIdentitiesFromTLS(ev)

		if result.OTLP != nil {
			sig := result.OTLP
			metrics.OTLPCapturedTotal.WithLabelValues(sig.SignalType).Inc()

			logArgs := []any{
				"signal_type", sig.SignalType,
				"service", sig.ServiceName,
				"batch_count", sig.BatchCount,
				"truncated", sig.IsTruncated,
				"pid", ev.PID,
			}

			if sig.IsTruncated {
				metrics.OTLPTruncatedTotal.Inc()
				logger.Info("OTLP captured (truncated)", logArgs...)
			} else {
				logger.Info("OTLP captured", logArgs...)
			}

			if fwd != nil {
				if err := fwd.Forward(sig); err != nil {
					metrics.OTLPForwardErrorsTotal.WithLabelValues(sig.SignalType).Inc()
					logger.Warn("OTLP forward failed", "error", err, "signal_type", sig.SignalType)
				} else {
					metrics.OTLPForwardedTotal.WithLabelValues(sig.SignalType).Inc()
					logger.Info("OTLP re-forwarded", "signal_type", sig.SignalType, "service", sig.ServiceName)
				}
			}

			select {
			case events <- otlpSignalToProto(sig, ev.PID):
			default:
			}
			continue
		}

		if result.JWT != nil {
			metrics.IdentitiesExtractedTotal.WithLabelValues("jwt").Inc()
			logger.Info("JWT captured",
				"subject", result.JWT.Subject,
				"issuer", result.JWT.Issuer,
				"pid", ev.PID,
			)
			select {
			case events <- jwtToProto(result.JWT, ev.PID):
			default:
			}
		}

		if result.MCP != nil {
			metrics.IdentitiesExtractedTotal.WithLabelValues("mcp").Inc()
			logger.Info("MCP tool call captured",
				"method", result.MCP.Method,
				"pid", ev.PID,
			)
			select {
			case events <- mcpToProto(result.MCP, ev.PID):
			default:
			}
		}

		if result.Boundary != nil {
			metrics.IdentitiesExtractedTotal.WithLabelValues("boundary").Inc()
			logger.Info("Boundary token captured",
				"token_type", result.Boundary.TokenType,
				"pid", ev.PID,
			)
			select {
			case events <- boundaryToProto(result.Boundary, ev.PID):
			default:
			}
		}
	}
}

// runCertEventLoop reads cert DER events, extracts SPIFFE IDs, evaluates policy,
// and sends events (SPIFFE observation + any POLICY_VIOLATION) to the stream.
// If tcLoader is non-nil, denied flows are inserted into the TC drop map.
func runCertEventLoop(ctx context.Context, cert *bpf.CertLoader, pol *policy.Evaluator, tc *bpf.TCLoader, events chan<- *apiv1.ReflectorEvent, logger *slog.Logger) {
	logger.Info("cert event loop started")
	for {
		data, err := cert.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("reading cert event", "error", err)
			continue
		}

		ev, err := bpf.ParseCertEvent(data)
		if err != nil {
			logger.Warn("parsing cert event", "error", err)
			continue
		}

		id, err := extract.ParseSPIFFEFromDER(ev.DER)
		if err != nil || id == nil {
			continue // not a SPIFFE SVID — skip silently
		}

		meta, _ := extract.ExtractCertMetadataFromDER(ev.DER)
		metrics.IdentitiesExtractedTotal.WithLabelValues("spiffe").Inc()

		protoEv := spiffeToProto(id, meta, ev.PID)
		select {
		case events <- protoEv:
		default:
		}

		result := pol.Eval(ctx, policy.Input{
			SPIFFEID: id.Raw,
			SrcAddr:  protoEv.SourceAddr,
			DstAddr:  protoEv.DestAddr,
			PID:      ev.PID,
		})

		if !result.Allow {
			logger.Warn("POLICY VIOLATION",
				"spiffe_id", id.Raw,
				"rule", result.Reason,
				"pid", ev.PID,
			)
			metrics.IdentitiesExtractedTotal.WithLabelValues("policy_violation").Inc()
			select {
			case events <- policyViolationToProto(protoEv, result.Reason):
			default:
			}
			if tc != nil {
				enforceTC(tc, ev.PID, logger)
			}
		} else {
			logger.Info("SPIFFE ID captured",
				"id", id.Raw,
				"trust_domain", id.TrustDomain,
				"path", id.Path,
				"pid", ev.PID,
			)
		}
	}
}

// connectionEventToProto converts a kprobe ConnectionEvent to a ReflectorEvent.
func connectionEventToProto(ev *extract.ConnectionEvent) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		Timestamp:    timestamppb.New(time.Now()),
		EventType:    apiv1.ReflectorEvent_CONNECTION_OPEN,
		IdentityType: apiv1.ReflectorEvent_UNKNOWN,
		SourceAddr:   fmt.Sprintf("%s:%d", ev.SrcIP, ev.SrcPort),
		DestAddr:     fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort),
		Protocol:     protocolName(ev.Protocol),
		Pid:          ev.PID,
	}
}

// otlpSignalToProto converts a captured OTLP signal to a ReflectorEvent.
func otlpSignalToProto(sig *extract.OTLPSignal, pid uint32) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		Timestamp:      timestamppb.New(time.Now()),
		EventType:      apiv1.ReflectorEvent_DATA_EXCHANGE,
		IdentityType:   apiv1.ReflectorEvent_OTEL,
		SourceIdentity: "otel:" + sig.ServiceName,
		OtelService:    sig.ServiceName,
		OtelSignalType: sig.SignalType,
		OtelSpanCount:  uint32(sig.BatchCount),
		Pid:            pid,
	}
}

// jwtToProto converts extracted JWT claims to a ReflectorEvent.
func jwtToProto(jwt *extract.JWTIdentity, pid uint32) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		Timestamp:      timestamppb.New(time.Now()),
		EventType:      apiv1.ReflectorEvent_DATA_EXCHANGE,
		IdentityType:   apiv1.ReflectorEvent_JWT,
		SourceIdentity: jwt.Subject,
		Pid:            pid,
	}
}

// mcpToProto converts an extracted MCP tool call to a ReflectorEvent.
func mcpToProto(mcp *extract.MCPToolCall, pid uint32) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		Timestamp:    timestamppb.New(time.Now()),
		EventType:    apiv1.ReflectorEvent_DATA_EXCHANGE,
		IdentityType: apiv1.ReflectorEvent_MCP,
		McpToolName:  mcp.Method,
		Pid:          pid,
	}
}

// boundaryToProto converts a captured Boundary token to a ReflectorEvent.
func boundaryToProto(bt *extract.BoundaryToken, pid uint32) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		Timestamp:            timestamppb.New(time.Now()),
		EventType:            apiv1.ReflectorEvent_DATA_EXCHANGE,
		IdentityType:         apiv1.ReflectorEvent_JWT, // nearest semantic match — opaque bearer
		BoundarySessionToken: bt.Raw,
		BoundaryTokenType:    string(bt.TokenType),
		Pid:                  pid,
	}
}

// spiffeToProto converts a parsed SPIFFE identity + cert metadata to a ReflectorEvent.
func spiffeToProto(id *extract.SPIFFEIdentity, meta extract.CertMetadata, pid uint32) *apiv1.ReflectorEvent {
	ev := &apiv1.ReflectorEvent{
		Timestamp:             timestamppb.New(time.Now()),
		EventType:             apiv1.ReflectorEvent_DATA_EXCHANGE,
		IdentityType:          apiv1.ReflectorEvent_SPIFFE,
		SourceIdentity:        id.Raw,
		Pid:                   pid,
		CertSerial:            meta.Serial,
		CertIssuerFingerprint: meta.IssuerFingerprint,
	}
	if !meta.Expiry.IsZero() {
		ev.CertExpiry = timestamppb.New(meta.Expiry)
	}
	return ev
}

// enforceTC looks up the PID's active TCP connections and inserts each into
// the TC deny map so the kernel drops subsequent packets on those flows.
func enforceTC(tc *bpf.TCLoader, pid uint32, logger *slog.Logger) {
	conns, err := bpf.ConnsByPID(pid)
	if err != nil {
		logger.Warn("TC enforce: could not read proc connections", "pid", pid, "error", err)
		return
	}
	for _, c := range conns {
		if err := tc.DenyFlow(c.SrcIP, c.DstIP, c.DstPort); err != nil {
			logger.Warn("TC enforce: DenyFlow failed", "error", err)
		}
	}
}

func policyViolationToProto(observed *apiv1.ReflectorEvent, rule string) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		Timestamp:      timestamppb.New(time.Now()),
		EventType:      apiv1.ReflectorEvent_POLICY_VIOLATION,
		IdentityType:   apiv1.ReflectorEvent_SPIFFE,
		SourceIdentity: observed.SourceIdentity,
		SourceAddr:     observed.SourceAddr,
		DestAddr:       observed.DestAddr,
		Pid:            observed.Pid,
		PolicyRule:     rule,
	}
}

// runLibCryptoScanner periodically scans /proc/*/maps for libcrypto instances
// and attaches d2i_X509 uprobes to any new ones. This makes SPIFFE extraction
// work for containerized workloads that ship their own libcrypto (different inode
// from the host library). Runs at startup and every 30s thereafter.
func runLibCryptoScanner(ctx context.Context, cert *bpf.CertLoader, logger *slog.Logger) {
	scan := func() {
		instances, err := bpf.ScanProcForLibCrypto()
		if err != nil {
			logger.Warn("proc libcrypto scan failed", "error", err)
			return
		}
		for _, inst := range instances {
			if err := cert.AttachToExecutable(inst.Path); err != nil {
				logger.Debug("uprobe attach skipped", "path", inst.Path, "error", err)
			}
		}
		logger.Debug("libcrypto scan complete", "attached_total", cert.AttachedCount())
	}

	scan() // immediate scan at startup
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}

func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("proto/%d", proto)
	}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

