// Package metrics defines Prometheus metrics for the reflector and sidecar.
// ADR-005: Prometheus + Perses for crawl, OTel for walk/run.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Reflector metrics (cmd/reflector).
var (
	EBPFEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "reflector_ebpf_events_total",
		Help: "Total events read from eBPF ring buffer.",
	}, []string{"type"}) // type: connect, accept

	EventsDroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflector_events_dropped_total",
		Help: "Events dropped due to ring buffer overflow.",
	})

	ConnectionsObservedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "reflector_connections_observed_total",
		Help: "Connections observed by protocol.",
	}, []string{"protocol"})

	IdentitiesExtractedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "reflector_identities_extracted_total",
		Help: "Identities successfully extracted.",
	}, []string{"type"}) // type: spiffe, jwt, mcp

	IdentityExtractionErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflector_identity_extraction_errors_total",
		Help: "Identity extraction failures.",
	})

	StreamEventsSentTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflector_stream_events_sent_total",
		Help: "Events sent to sidecar via gRPC stream.",
	})

	StreamReconnectsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflector_stream_reconnects_total",
		Help: "gRPC stream reconnection count.",
	})

	// OTLP capture + re-forward metrics (ADR-007).
	OTLPCapturedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "reflector_otel_captured_total",
		Help: "OTLP exports captured from SSL_write plaintext.",
	}, []string{"signal_type"}) // signal_type: traces, metrics, logs

	OTLPTruncatedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflector_otel_truncated_total",
		Help: "OTLP captures skipped due to truncation (payload > MAX_CAPTURE_BYTES).",
	})

	OTLPForwardedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "reflector_otel_forwarded_total",
		Help: "OTLP exports successfully re-forwarded to the configured collector.",
	}, []string{"signal_type"})

	OTLPForwardErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "reflector_otel_forward_errors_total",
		Help: "OTLP re-forward failures (truncation, network, HTTP error).",
	}, []string{"signal_type"})
)

// Sidecar metrics (cmd/reflector-map).
var (
	StreamEventsReceivedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflectormap_stream_events_received_total",
		Help: "Events received from reflector stream.",
	})

	SessionMapActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "reflectormap_session_map_active_connections",
		Help: "Current active connections in session map.",
	})

	SessionMapIdentitiesActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "reflectormap_session_map_identities_active",
		Help: "Distinct identities with active connections.",
	})

	SessionMapStaleTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reflectormap_session_map_stale_total",
		Help: "Connections aged out due to TTL expiry.",
	})
)

// RegisterReflector registers all reflector metrics.
func RegisterReflector(reg prometheus.Registerer) {
	reg.MustRegister(
		EBPFEventsTotal,
		EventsDroppedTotal,
		ConnectionsObservedTotal,
		IdentitiesExtractedTotal,
		IdentityExtractionErrorsTotal,
		StreamEventsSentTotal,
		StreamReconnectsTotal,
		OTLPCapturedTotal,
		OTLPTruncatedTotal,
		OTLPForwardedTotal,
		OTLPForwardErrorsTotal,
	)
}

// RegisterSidecar registers all sidecar metrics.
func RegisterSidecar(reg prometheus.Registerer) {
	reg.MustRegister(
		StreamEventsReceivedTotal,
		SessionMapActiveConnections,
		SessionMapIdentitiesActive,
		SessionMapStaleTotal,
	)
}
