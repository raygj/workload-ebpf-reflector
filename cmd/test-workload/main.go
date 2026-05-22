// Package main is a test workload that generates observable traffic patterns
// for the eBPF reflector to capture. It simulates:
//
//   - An mTLS server with a SPIFFE SVID certificate
//   - A client making HTTPS requests with JWT bearer tokens
//   - A client making MCP tool calls (JSON-RPC over HTTPS)
//   - An OTel-instrumented agent emitting OTLP/HTTP traces, metrics, and logs
//
// All connections use Go's crypto/tls (not OpenSSL), so the kprobe path
// (5-tuple extraction) will observe them. The uprobe TLS path (SSL_write)
// requires OpenSSL and is tested separately.
//
// OTLP export note: OTLP is sent to the --otel-collector address over plain HTTP
// (not TLS) unless you configure a TLS collector. In the Docker Compose demo,
// the reflector captures OTLP from OpenSSL-based agents (Python OTel SDK);
// this workload demonstrates the protobuf wire format.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func main() {
	listenAddr := flag.String("listen", ":8443", "mTLS server listen address")
	targetAddr := flag.String("target", "", "target address to connect to (default: self)")
	interval := flag.Duration("interval", 2*time.Second, "interval between client requests")
	otelCollector := flag.String("otel-collector", "",
		"OTLP/HTTP collector endpoint for trace emission (e.g. http://collector:4318). "+
			"Leave empty to disable OTLP emission.")
	serviceName := flag.String("service-name", "test-agent", "OTel service.name attribute")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Generate SPIFFE SVID certificate
	spiffeID := "spiffe://demo.cluster/ns/default/sa/test-agent"
	cert, pool := generateSVIDCert(spiffeID)

	logger.Info("test workload starting",
		"spiffe_id", spiffeID,
		"listen", *listenAddr,
		"interval", interval.String(),
		"otel_collector", *otelCollector,
		"service_name", *serviceName,
	)

	// Start mTLS server
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/secrets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"key":"value"}}`))
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"content":[]},"id":1}`))
	})

	server := &http.Server{
		Addr:      *listenAddr,
		Handler:   mux,
		TLSConfig: serverTLS,
	}

	lis, err := tls.Listen("tcp", *listenAddr, serverTLS)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}

	go func() {
		logger.Info("mTLS server listening", "addr", lis.Addr().String())
		if err := server.Serve(lis); err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	// Determine target
	target := *targetAddr
	if target == "" {
		_, port, _ := net.SplitHostPort(lis.Addr().String())
		target = "localhost:" + port
	}

	// Client TLS config (mTLS with same cert)
	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		InsecureSkipVerify: true, //nolint:gosec // lab test only
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
		Timeout:   5 * time.Second,
	}

	// Plain HTTP client for OTLP (no TLS required for local collector)
	otlpClient := &http.Client{Timeout: 5 * time.Second}

	// Build a fake JWT
	jwt := buildTestJWT("spiffe://demo.cluster/ns/default/sa/test-agent", "vault-demo")

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()

	// Traffic generation loop
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	requestNum := 0
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down test workload")
			return
		case <-ticker.C:
			requestNum++
			switch requestNum % 4 {
			case 0:
				// HTTPS with JWT
				doRequest(client, logger, "https://"+target+"/api/secrets", jwt, nil)
			case 1:
				// MCP tool call
				mcpBody := map[string]any{
					"jsonrpc": "2.0",
					"method":  "tools/call",
					"params":  map[string]any{"name": "vault_read", "arguments": map[string]string{"path": "secret/data/app"}},
					"id":      requestNum,
				}
				doRequest(client, logger, "https://"+target+"/mcp", jwt, mcpBody)
			case 2:
				// Health check (no JWT)
				doRequest(client, logger, "https://"+target+"/health", "", nil)
			case 3:
				// OTLP trace export
				if *otelCollector != "" {
					emitOTLPTraces(otlpClient, logger, *otelCollector, *serviceName, requestNum)
				}
			}
		}
	}
}

// emitOTLPTraces sends a minimal ExportTraceServiceRequest to the OTLP/HTTP collector.
// The protobuf is built manually with protowire — no OTel SDK dependency (ADR-007).
func emitOTLPTraces(client *http.Client, logger *slog.Logger, collectorURL, serviceName string, requestNum int) {
	body := buildOTLPProtoBody(serviceName)
	url := collectorURL + "/v1/traces"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logger.Warn("OTLP request build failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("OTLP export failed", "url", url, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	logger.Info("OTLP traces exported",
		"collector", collectorURL,
		"service", serviceName,
		"status", resp.StatusCode,
		"request_num", requestNum,
	)
}

// buildOTLPProtoBody builds a minimal ExportTraceServiceRequest protobuf with:
//   - ResourceSpans.resource.attributes["service.name"]
//   - ScopeSpans containing one Span with MCP identity attributes
//
// Uses protowire directly — no generated OTLP proto types (ADR-007).
//
// Wire field numbers (OTLP proto spec):
//
//	Span: trace_id=1, span_id=2, name=5, kind=6(varint), start=7(fixed64), end=8(fixed64),
//	      attributes=9(repeated), status=15
//	Status: code=3(varint)  StatusCode: OK=1
//	ScopeSpans: scope=1, spans=2
//	InstrumentationScope: name=1
//	ResourceSpans: resource=1, scope_spans=2
//	ExportTraceServiceRequest: resource_spans=1
func buildOTLPProtoBody(serviceName string) []byte {
	now := uint64(time.Now().UnixNano())

	// Generate random TraceID (16 bytes) and SpanID (8 bytes).
	var traceID [16]byte
	var spanID [8]byte
	_, _ = rand.Read(traceID[:])
	_, _ = rand.Read(spanID[:])

	// stringAnyValue encodes AnyValue { string_value (field 1): s }.
	stringAnyValue := func(s string) []byte {
		v := protowire.AppendTag(nil, 1, protowire.BytesType)
		return protowire.AppendBytes(v, []byte(s))
	}

	// kvAttr encodes KeyValue { key (field 1), value.string_value (field 2→1) }.
	kvAttr := func(key, val string) []byte {
		kv := protowire.AppendTag(nil, 1, protowire.BytesType)
		kv = protowire.AppendBytes(kv, []byte(key))
		kv = protowire.AppendTag(kv, 2, protowire.BytesType)
		kv = protowire.AppendBytes(kv, stringAnyValue(val))
		return kv
	}

	// Resource { attributes (field 1): service.name }
	resource := protowire.AppendTag(nil, 1, protowire.BytesType)
	resource = protowire.AppendBytes(resource, kvAttr("service.name", serviceName))

	// Status { code (field 3): STATUS_CODE_OK = 1 }
	status := protowire.AppendTag(nil, 3, protowire.VarintType)
	status = protowire.AppendVarint(status, 1)

	// Span { trace_id=1, span_id=2, name=5, kind=6, start=7, end=8, attributes=9×3, status=15 }
	span := protowire.AppendTag(nil, 1, protowire.BytesType)
	span = protowire.AppendBytes(span, traceID[:])
	span = protowire.AppendTag(span, 2, protowire.BytesType)
	span = protowire.AppendBytes(span, spanID[:])
	span = protowire.AppendTag(span, 5, protowire.BytesType)
	span = protowire.AppendBytes(span, []byte("mcp.tools.call"))
	span = protowire.AppendTag(span, 6, protowire.VarintType)
	span = protowire.AppendVarint(span, 3) // SPAN_KIND_CLIENT
	span = protowire.AppendTag(span, 7, protowire.Fixed64Type)
	span = protowire.AppendFixed64(span, now)
	span = protowire.AppendTag(span, 8, protowire.Fixed64Type)
	span = protowire.AppendFixed64(span, now+1_000_000) // 1ms synthetic duration
	for _, attr := range [][]byte{
		kvAttr("mcp.tool", "vault_read"),
		kvAttr("mcp.server", "vault-mcp"),
		kvAttr("spiffe.id", "spiffe://demo.cluster/ns/default/sa/test-agent"),
	} {
		span = protowire.AppendTag(span, 9, protowire.BytesType)
		span = protowire.AppendBytes(span, attr)
	}
	span = protowire.AppendTag(span, 15, protowire.BytesType)
	span = protowire.AppendBytes(span, status)

	// InstrumentationScope { name (field 1) }
	scope := protowire.AppendTag(nil, 1, protowire.BytesType)
	scope = protowire.AppendBytes(scope, []byte("reflector-demo"))

	// ScopeSpans { scope (field 1), spans (field 2) }
	scopeSpans := protowire.AppendTag(nil, 1, protowire.BytesType)
	scopeSpans = protowire.AppendBytes(scopeSpans, scope)
	scopeSpans = protowire.AppendTag(scopeSpans, 2, protowire.BytesType)
	scopeSpans = protowire.AppendBytes(scopeSpans, span)

	// ResourceSpans { resource (field 1), scope_spans (field 2) }
	rs := protowire.AppendTag(nil, 1, protowire.BytesType)
	rs = protowire.AppendBytes(rs, resource)
	rs = protowire.AppendTag(rs, 2, protowire.BytesType)
	rs = protowire.AppendBytes(rs, scopeSpans)

	// ExportTraceServiceRequest { resource_spans (field 1) }
	req := protowire.AppendTag(nil, 1, protowire.BytesType)
	req = protowire.AppendBytes(req, rs)

	return req
}

func doRequest(client *http.Client, logger *slog.Logger, url, jwt string, body any) {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}

	method := "GET"
	if bodyReader != nil {
		method = "POST"
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		logger.Warn("request build failed", "url", url, "error", err)
		return
	}

	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("request failed", "url", url, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	logger.Info("request completed",
		"method", method,
		"url", url,
		"status", resp.StatusCode,
		"has_jwt", jwt != "",
	)
}

func generateSVIDCert(spiffeID string) (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	u, _ := url.Parse(spiffeID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-workload"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)

	return cert, pool
}

func buildTestJWT(sub, iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]string{"sub": sub, "iss": iss, "aud": "reflector-demo"})
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("test-signature-not-verified"))
	return fmt.Sprintf("%s.%s.%s", header, payloadEnc, sig)
}
