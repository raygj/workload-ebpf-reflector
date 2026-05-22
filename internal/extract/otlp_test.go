package extract

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildOTLPProto constructs a minimal ExportTraceServiceRequest protobuf with
// one ResourceSpans containing a resource with service.name = serviceName.
// Used to build test fixtures without importing the full OTLP proto package.
//
// Wire structure built:
//
//	ExportTraceServiceRequest {
//	  resource_spans (field 1): ResourceSpans {
//	    resource (field 1): Resource {
//	      attributes (field 1): KeyValue { key: "service.name", value: { string_value: serviceName } }
//	    }
//	  }
//	}
func buildOTLPProto(serviceName string) []byte {
	// AnyValue { string_value (field 1): serviceName }
	anyValue := protowire.AppendTag(nil, 1, protowire.BytesType)
	anyValue = protowire.AppendBytes(anyValue, []byte(serviceName))

	// KeyValue { key (field 1): "service.name", value (field 2): anyValue }
	kv := protowire.AppendTag(nil, 1, protowire.BytesType)
	kv = protowire.AppendBytes(kv, []byte("service.name"))
	kv = protowire.AppendTag(kv, 2, protowire.BytesType)
	kv = protowire.AppendBytes(kv, anyValue)

	// Resource { attributes (field 1): kv }
	resource := protowire.AppendTag(nil, 1, protowire.BytesType)
	resource = protowire.AppendBytes(resource, kv)

	// ResourceSpans { resource (field 1): resource }
	rs := protowire.AppendTag(nil, 1, protowire.BytesType)
	rs = protowire.AppendBytes(rs, resource)

	// ExportTraceServiceRequest { resource_spans (field 1): rs }
	req := protowire.AppendTag(nil, 1, protowire.BytesType)
	req = protowire.AppendBytes(req, rs)

	return req
}

// buildOTLPHTTPRequest builds a synthetic OTLP/HTTP request as it appears
// in SSL_write plaintext.
func buildOTLPHTTPRequest(path string, body []byte) []byte {
	headers := fmt.Sprintf("POST %s HTTP/1.1\r\nContent-Type: application/x-protobuf\r\nContent-Length: %d\r\n\r\n",
		path, len(body))
	return append([]byte(headers), body...)
}

// buildOTLPGRPCRequest builds a synthetic OTLP/gRPC request as it appears
// in SSL_write plaintext (HTTP/2 headers + gRPC length prefix).
func buildOTLPGRPCRequest(path string, body []byte) []byte {
	// Simplified: write the HTTP/1.1-like headers for detection purposes
	// plus the 5-byte gRPC length prefix + body.
	grpcFrame := make([]byte, 5)
	grpcFrame[0] = 0 // no compression
	l := len(body)
	grpcFrame[1] = byte(l >> 24)
	grpcFrame[2] = byte(l >> 16)
	grpcFrame[3] = byte(l >> 8)
	grpcFrame[4] = byte(l)

	headers := fmt.Sprintf("POST %s HTTP/2\r\nContent-Type: application/grpc\r\nContent-Length: %d\r\n\r\n",
		path, 5+len(body))
	payload := append([]byte(headers), grpcFrame...)
	return append(payload, body...)
}

// --- Tests ---

func TestExtractOTLPFromTLS_TracesHTTP(t *testing.T) {
	proto := buildOTLPProto("payment-service")
	plaintext := buildOTLPHTTPRequest("/v1/traces", proto)

	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig == nil {
		t.Fatal("expected OTLPSignal, got nil")
	}
	if sig.SignalType != "traces" {
		t.Errorf("SignalType = %q, want %q", sig.SignalType, "traces")
	}
	if sig.ServiceName != "payment-service" {
		t.Errorf("ServiceName = %q, want %q", sig.ServiceName, "payment-service")
	}
	if sig.BatchCount != 1 {
		t.Errorf("BatchCount = %d, want 1", sig.BatchCount)
	}
	if sig.IsTruncated {
		t.Error("IsTruncated = true, want false")
	}
	if len(sig.RawBody) == 0 {
		t.Error("RawBody is empty, want the protobuf bytes")
	}
}

func TestExtractOTLPFromTLS_MetricsHTTP(t *testing.T) {
	proto := buildOTLPProto("metrics-emitter")
	plaintext := buildOTLPHTTPRequest("/v1/metrics", proto)

	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil || sig == nil {
		t.Fatalf("expected signal, got nil/err: %v", err)
	}
	if sig.SignalType != "metrics" {
		t.Errorf("SignalType = %q, want %q", sig.SignalType, "metrics")
	}
	if sig.ServiceName != "metrics-emitter" {
		t.Errorf("ServiceName = %q, want %q", sig.ServiceName, "metrics-emitter")
	}
}

func TestExtractOTLPFromTLS_LogsHTTP(t *testing.T) {
	proto := buildOTLPProto("log-producer")
	plaintext := buildOTLPHTTPRequest("/v1/logs", proto)

	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil || sig == nil {
		t.Fatalf("expected signal, got nil/err: %v", err)
	}
	if sig.SignalType != "logs" {
		t.Errorf("SignalType = %q, want %q", sig.SignalType, "logs")
	}
}

func TestExtractOTLPFromTLS_GRPCTraces(t *testing.T) {
	proto := buildOTLPProto("grpc-service")
	path := "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
	plaintext := buildOTLPGRPCRequest(path, proto)

	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil || sig == nil {
		t.Fatalf("expected signal, got nil/err: %v", err)
	}
	if sig.SignalType != "traces" {
		t.Errorf("SignalType = %q, want %q", sig.SignalType, "traces")
	}
	if sig.ServiceName != "grpc-service" {
		t.Errorf("ServiceName = %q, want %q", sig.ServiceName, "grpc-service")
	}
}

func TestExtractOTLPFromTLS_NotOTLP(t *testing.T) {
	cases := [][]byte{
		[]byte("GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("POST /api/secrets HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}"),
		[]byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`),
		[]byte("not http at all"),
		nil,
		{},
	}
	for _, tc := range cases {
		sig, err := ExtractOTLPFromTLS(tc)
		if err != nil {
			t.Errorf("unexpected error for %q: %v", string(tc), err)
		}
		if sig != nil {
			t.Errorf("expected nil for non-OTLP input %q, got %+v", string(tc), sig)
		}
	}
}

func TestExtractOTLPFromTLS_Truncated(t *testing.T) {
	proto := buildOTLPProto("truncated-svc")
	// Report a larger Content-Length than what we actually include
	headers := fmt.Sprintf("POST /v1/traces HTTP/1.1\r\nContent-Type: application/x-protobuf\r\nContent-Length: %d\r\n\r\n",
		len(proto)+500)
	plaintext := append([]byte(headers), proto...)

	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil || sig == nil {
		t.Fatalf("expected signal, got nil/err: %v", err)
	}
	if !sig.IsTruncated {
		t.Error("IsTruncated = false, want true")
	}
	if sig.RawBody != nil {
		t.Error("RawBody should be nil for truncated events")
	}
}

func TestExtractOTLPFromTLS_MultipleBatches(t *testing.T) {
	// Build a proto with 3 ResourceSpans
	rs := buildOTLPProto("svc-a") // 1 ResourceSpans
	// Append two more ResourceSpans (same structure)
	rs2 := protowire.AppendTag(nil, 1, protowire.BytesType)
	rs2 = protowire.AppendBytes(rs2, buildOTLPProto("svc-b")[2:]) // reuse inner bytes
	rs3 := protowire.AppendTag(nil, 1, protowire.BytesType)
	rs3 = protowire.AppendBytes(rs3, buildOTLPProto("svc-c")[2:])
	multi := append(append(rs, rs2...), rs3...)

	plaintext := buildOTLPHTTPRequest("/v1/traces", multi)
	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil || sig == nil {
		t.Fatalf("expected signal, got nil/err: %v", err)
	}
	if sig.BatchCount < 1 {
		t.Errorf("BatchCount = %d, want >= 1", sig.BatchCount)
	}
}

func TestExtractOTLPServiceName_Empty(t *testing.T) {
	// Proto with no service.name attribute
	rs := protowire.AppendTag(nil, 1, protowire.BytesType)
	rs = protowire.AppendBytes(rs, []byte{}) // empty ResourceSpans
	req := protowire.AppendTag(nil, 1, protowire.BytesType)
	req = protowire.AppendBytes(req, rs)
	plaintext := buildOTLPHTTPRequest("/v1/traces", req)

	sig, err := ExtractOTLPFromTLS(plaintext)
	if err != nil || sig == nil {
		t.Fatalf("expected signal, got nil/err: %v", err)
	}
	if sig.SignalType != "traces" {
		t.Errorf("SignalType = %q, want traces", sig.SignalType)
	}
	// ServiceName should be empty — not an error
	if sig.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty", sig.ServiceName)
	}
}
