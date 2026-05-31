// Package rotation_test exercises the full cert rotation anomaly detection path:
// reflector (gRPC stream client) → stream server → session map (RotationTracker)
// → rotation entries queryable via GET /sessions?status=rotation_*.
//
// This test wires the same stack as cmd/reflector-map/main.go — no mocks.
package rotation_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"context"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"github.com/raygj/workload-ebpf-reflector/internal/session"
	"github.com/raygj/workload-ebpf-reflector/internal/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func rotationStack(t *testing.T) (sendEvent func(*apiv1.ReflectorEvent), querySessions func(status string) []session.Entry, teardown func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sessionMap := session.NewMap(60 * time.Second)

	handler := func(ev *apiv1.ReflectorEvent) { sessionMap.HandleEvent(ev) }

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	apiv1.RegisterReflectorServiceServer(grpcServer, stream.NewServer(handler, logger))
	go func() { _ = grpcServer.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	rpcStream, err := apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	if err != nil {
		cancel()
		_ = conn.Close()
		t.Fatalf("StreamEvents: %v", err)
	}

	apiHandler := session.NewAPI(sessionMap).Handler()

	sendFn := func(ev *apiv1.ReflectorEvent) {
		if err := rpcStream.Send(ev); err != nil {
			t.Errorf("Send: %v", err)
		}
	}

	queryFn := func(status string) []session.Entry {
		req := httptest.NewRequest("GET", fmt.Sprintf("/sessions?status=%s", status), nil)
		w := httptest.NewRecorder()
		apiHandler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /sessions?status=%s: status %d", status, w.Code)
		}
		var entries []session.Entry
		if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
			t.Fatalf("decode sessions: %v", err)
		}
		return entries
	}

	teardownFn := func() {
		_ = rpcStream.CloseSend()
		cancel()
		_ = conn.Close()
		grpcServer.Stop()
	}

	return sendFn, queryFn, teardownFn
}

// openEvent creates a CONNECTION_OPEN to establish the session map entry.
func openEvent(nodeID, src, dst, spiffeID string, pid uint32) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		NodeId:         nodeID,
		Timestamp:      timestamppb.Now(),
		EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
		SourceAddr:     src,
		DestAddr:       dst,
		Protocol:       "tcp",
		SourceIdentity: spiffeID,
		IdentityType:   apiv1.ReflectorEvent_SPIFFE,
		Pid:            pid,
	}
}

// certDataEvent creates a DATA_EXCHANGE carrying cert metadata, which triggers
// rotation classification in the session map.
func certDataEvent(nodeID, src, dst, spiffeID, serial, issuerFP string, issuedAt time.Time, lifetime time.Duration, pid uint32) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		NodeId:                nodeID,
		Timestamp:             timestamppb.New(issuedAt),
		EventType:             apiv1.ReflectorEvent_DATA_EXCHANGE,
		SourceAddr:            src,
		DestAddr:              dst,
		Protocol:              "tcp",
		SourceIdentity:        spiffeID,
		IdentityType:          apiv1.ReflectorEvent_SPIFFE,
		CertSerial:            serial,
		CertExpiry:            timestamppb.New(issuedAt.Add(lifetime)),
		CertIssuerFingerprint: issuerFP,
		Pid:                   pid,
	}
}

// TestScheduledRotationProducesNormalEntry verifies that a cert rotation
// arriving after the previous cert's expiry is classified as rotation_normal.
func TestScheduledRotationProducesNormalEntry(t *testing.T) {
	send, query, teardown := rotationStack(t)
	defer teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	src, dst := "10.0.0.1:52000", "vault.prod:8200"
	now := time.Now()

	send(openEvent("node-1", src, dst, spiffeID, 1000))
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-001", "fp-prod-ca", now, 24*time.Hour, 1000))
	time.Sleep(50 * time.Millisecond)

	// Second cert arrives after the first has expired — scheduled rotation.
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-002", "fp-prod-ca", now.Add(25*time.Hour), 24*time.Hour, 1000))
	time.Sleep(50 * time.Millisecond)

	entries := query("rotation_normal")
	if len(entries) != 1 {
		t.Fatalf("rotation_normal entries = %d, want 1", len(entries))
	}
	if entries[0].CertSerial != "serial-002" {
		t.Errorf("CertSerial = %q, want serial-002", entries[0].CertSerial)
	}
}

// TestEarlyRotationProducesEarlyEntry verifies that a cert rotation arriving
// well before the previous cert expires (same PID) is classified as rotation_early.
func TestEarlyRotationProducesEarlyEntry(t *testing.T) {
	send, query, teardown := rotationStack(t)
	defer teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	src, dst := "10.0.0.1:52001", "vault.prod:8200"
	now := time.Now()

	send(openEvent("node-1", src, dst, spiffeID, 1001))
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-001", "fp-prod-ca", now, 24*time.Hour, 1001))
	time.Sleep(50 * time.Millisecond)

	// Same PID rotates early (2h into a 24h cert).
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-002", "fp-prod-ca", now.Add(2*time.Hour), 24*time.Hour, 1001))
	time.Sleep(50 * time.Millisecond)

	entries := query("rotation_early")
	if len(entries) != 1 {
		t.Fatalf("rotation_early entries = %d, want 1", len(entries))
	}
	if entries[0].Identity != spiffeID {
		t.Errorf("Identity = %q, want %s", entries[0].Identity, spiffeID)
	}
}

// TestPodRestartDoesNotProduceEarlyEntry verifies the false-positive suppression:
// a pod restart (new PID, same SPIFFE path) that triggers early cert issuance
// is classified as rotation_normal, not rotation_early.
func TestPodRestartDoesNotProduceEarlyEntry(t *testing.T) {
	send, query, teardown := rotationStack(t)
	defer teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	src, dst := "10.0.0.1:52002", "vault.prod:8200"
	now := time.Now()

	// Pod A (PID 2000): first cert establishes baseline.
	send(openEvent("node-1", src, dst, spiffeID, 2000))
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-001", "fp-prod-ca", now, 24*time.Hour, 2000))
	time.Sleep(50 * time.Millisecond)

	// Pod B (PID 3000) starts 2h later — SPIRE immediately issues new cert.
	// Same connection key (same src) because the pod restart reuses the address.
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-002", "fp-prod-ca", now.Add(2*time.Hour), 24*time.Hour, 3000))
	time.Sleep(50 * time.Millisecond)

	earlyEntries := query("rotation_early")
	if len(earlyEntries) != 0 {
		t.Errorf("pod restart produced %d rotation_early entries, want 0 (false positive suppressed)", len(earlyEntries))
	}

	normalEntries := query("rotation_normal")
	if len(normalEntries) != 1 {
		t.Errorf("pod restart produced %d rotation_normal entries, want 1", len(normalEntries))
	}
}

// TestIssuerChangeProducesIssuerEntry verifies that a cert from a different CA
// is classified as rotation_issuer regardless of timing.
func TestIssuerChangeProducesIssuerEntry(t *testing.T) {
	send, query, teardown := rotationStack(t)
	defer teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	src, dst := "10.0.0.1:52004", "vault.prod:8200"
	now := time.Now()

	send(openEvent("node-1", src, dst, spiffeID, 4000))
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-001", "fp-prod-ca", now, 24*time.Hour, 4000))
	time.Sleep(50 * time.Millisecond)

	// New cert from a different issuer — issuer change takes priority over timing.
	send(certDataEvent("node-1", src, dst, spiffeID, "serial-002", "fp-different-ca", now.Add(25*time.Hour), 24*time.Hour, 4000))
	time.Sleep(50 * time.Millisecond)

	entries := query("rotation_issuer")
	if len(entries) != 1 {
		t.Fatalf("rotation_issuer entries = %d, want 1", len(entries))
	}
	if entries[0].CertIssuerFingerprint != "fp-different-ca" {
		t.Errorf("IssuerFingerprint = %q, want fp-different-ca", entries[0].CertIssuerFingerprint)
	}
}
