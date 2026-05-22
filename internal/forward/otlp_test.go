package forward

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/raygj/workload-ebpf-reflector/internal/extract"
)

func TestForwarder_ForwardTraces(t *testing.T) {
	var gotPath, gotContentType string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := NewForwarder(srv.URL)
	sig := &extract.OTLPSignal{
		SignalType:  "traces",
		ServiceName: "test-svc",
		RawBody:     []byte("fake-proto-body"),
	}

	if err := fwd.Forward(sig); err != nil {
		t.Fatalf("Forward returned error: %v", err)
	}
	if gotPath != "/v1/traces" {
		t.Errorf("path = %q, want /v1/traces", gotPath)
	}
	if gotContentType != "application/x-protobuf" {
		t.Errorf("Content-Type = %q, want application/x-protobuf", gotContentType)
	}
	if string(gotBody) != "fake-proto-body" {
		t.Errorf("body = %q, want fake-proto-body", string(gotBody))
	}
}

func TestForwarder_SkipsTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not have called collector — signal is truncated")
	}))
	defer srv.Close()

	fwd := NewForwarder(srv.URL)
	sig := &extract.OTLPSignal{
		SignalType:  "traces",
		IsTruncated: true,
		RawBody:     nil,
	}
	if err := fwd.Forward(sig); err == nil {
		t.Error("expected error for truncated signal, got nil")
	}
}

func TestForwarder_SkipsEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not have called collector — no body")
	}))
	defer srv.Close()

	fwd := NewForwarder(srv.URL)
	sig := &extract.OTLPSignal{
		SignalType: "metrics",
		RawBody:    nil,
	}
	if err := fwd.Forward(sig); err == nil {
		t.Error("expected error for empty body, got nil")
	}
}

func TestForwarder_HTTPErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	fwd := NewForwarder(srv.URL)
	sig := &extract.OTLPSignal{
		SignalType: "logs",
		RawBody:    []byte("proto"),
	}
	if err := fwd.Forward(sig); err == nil {
		t.Error("expected error for HTTP 400, got nil")
	}
}

func TestForwarder_MetricsPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := NewForwarder(srv.URL)
	sig := &extract.OTLPSignal{SignalType: "metrics", RawBody: []byte("m")}
	if err := fwd.Forward(sig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/v1/metrics" {
		t.Errorf("path = %q, want /v1/metrics", gotPath)
	}
}
