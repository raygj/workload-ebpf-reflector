// Package attest_test exercises the full attestation path:
// reflector (gRPC stream client) → stream server → session map → HTTP /attest.
//
// This test wires the stack the same way cmd/reflector-map/main.go does —
// no mocks, real sockets — so regressions in the wiring show up here.
package attest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"log/slog"
	"os"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"github.com/raygj/workload-ebpf-reflector/internal/session"
	"github.com/raygj/workload-ebpf-reflector/internal/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// stack wires the full reflector-map stack on ephemeral ports and returns
// a teardown function. Mirrors the wiring in cmd/reflector-map/main.go.
func stack(t *testing.T) (grpcAddr string, httpHandler http.Handler, teardown func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sessionMap := session.NewMap(60 * time.Second)

	handler := func(ev *apiv1.ReflectorEvent) { sessionMap.HandleEvent(ev) }

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("gRPC listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	apiv1.RegisterReflectorServiceServer(grpcServer, stream.NewServer(handler, logger))
	go func() { _ = grpcServer.Serve(lis) }()

	api := session.NewAPI(sessionMap)

	return lis.Addr().String(), api.Handler(), func() { grpcServer.Stop() }
}

// reflectorClient connects as a reflector DaemonSet would: opens the gRPC stream
// and returns a send function + a close function.
func reflectorClient(t *testing.T, grpcAddr string) (send func(*apiv1.ReflectorEvent), close func()) {
	t.Helper()

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	rpcStream, err := apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	if err != nil {
		cancel()
		_ = conn.Close()
		t.Fatalf("StreamEvents: %v", err)
	}

	return func(ev *apiv1.ReflectorEvent) {
			if err := rpcStream.Send(ev); err != nil {
				t.Errorf("Send: %v", err)
			}
		}, func() {
			_ = rpcStream.CloseSend()
			cancel()
			_ = conn.Close()
		}
}

func attest(t *testing.T, handler http.Handler, pid uint32, src, dst string) session.AttestResult {
	t.Helper()
	url := fmt.Sprintf("/attest?pid=%d&src=%s&dst=%s", pid, src, dst)
	req := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", url, w.Code)
	}
	var result session.AttestResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode /attest response: %v", err)
	}
	return result
}

// TestAttestKernelConfidenceEndToEnd is the Sprint 10 acceptance test:
// agent connects → reflector observes cert → middleware queries /attest → kernel confidence.
func TestAttestKernelConfidenceEndToEnd(t *testing.T) {
	grpcAddr, httpHandler, teardown := stack(t)
	defer teardown()

	send, closeStream := reflectorClient(t, grpcAddr)
	defer closeStream()

	send(&apiv1.ReflectorEvent{
		NodeId:         "node-1",
		Timestamp:      timestamppb.Now(),
		EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
		SourceAddr:     "10.0.0.1:52100",
		DestAddr:       "vault.prod:8200",
		Protocol:       "tcp",
		SourceIdentity: "spiffe://prod/agent/deploy",
		IdentityType:   apiv1.ReflectorEvent_SPIFFE,
		Pid:            4242,
	})

	// Allow the event to propagate through the gRPC stream to the session map.
	time.Sleep(50 * time.Millisecond)

	result := attest(t, httpHandler, 4242, "10.0.0.1:52100", "vault.prod:8200")

	if result.Confidence != "kernel" {
		t.Errorf("Confidence = %q, want kernel", result.Confidence)
	}
	if result.SpiffeID != "spiffe://prod/agent/deploy" {
		t.Errorf("SpiffeID = %q, want spiffe://prod/agent/deploy", result.SpiffeID)
	}
	if result.ObservedAt.IsZero() {
		t.Error("ObservedAt is zero, want a valid timestamp")
	}
}

// TestAttestFailOpenOnUnknownConnection verifies the fail-open contract:
// a connection the reflector has never seen returns jwt-only, never an error.
func TestAttestFailOpenOnUnknownConnection(t *testing.T) {
	_, httpHandler, teardown := stack(t)
	defer teardown()

	result := attest(t, httpHandler, 9999, "10.0.0.99:50099", "vault.prod:8200")

	if result.Confidence != "jwt-only" {
		t.Errorf("Confidence = %q, want jwt-only for unknown connection", result.Confidence)
	}
}

// TestAttestResponseUnder1ms verifies the latency acceptance criterion:
// in-memory lookup must be < 1ms even with entries in the map.
func TestAttestResponseUnder1ms(t *testing.T) {
	grpcAddr, httpHandler, teardown := stack(t)
	defer teardown()

	send, closeStream := reflectorClient(t, grpcAddr)
	defer closeStream()

	// Seed the map with a few connections so the scan isn't trivial.
	for i := range 10 {
		send(&apiv1.ReflectorEvent{
			NodeId:         "node-1",
			Timestamp:      timestamppb.Now(),
			EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
			SourceAddr:     fmt.Sprintf("10.0.0.%d:52%d", i, 200+i),
			DestAddr:       "vault.prod:8200",
			Protocol:       "tcp",
			SourceIdentity: fmt.Sprintf("spiffe://prod/agent/%d", i),
			IdentityType:   apiv1.ReflectorEvent_SPIFFE,
			Pid:            uint32(1000 + i),
		})
	}
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest("GET", "/attest?pid=1000&src=10.0.0.0:52200&dst=vault.prod:8200", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	httpHandler.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if elapsed > time.Millisecond {
		t.Errorf("attest took %v, want < 1ms", elapsed)
	}
}
