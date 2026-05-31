// Package profile_test exercises the full behavioral fingerprinting path:
// reflector (gRPC stream) → session map (ProfileTracker) → GET /profile.
//
// Design principle: confirm gRPC delivery via GET /sessions before querying
// GET /profile. This avoids the window-boundary race (polling by wall clock
// can cross a window boundary between when events are delivered and when the
// profile is queried, making the current window appear empty).
package profile_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"github.com/raygj/workload-ebpf-reflector/internal/session"
	"github.com/raygj/workload-ebpf-reflector/internal/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// testWindow is wide enough to hold all events between driveWindow
	// calls, but short enough to make tests fast.
	testWindow = 300 * time.Millisecond
	learnMin   = 3 // must match internal session.profileLearnMin
)

type testStack struct {
	send       func(*apiv1.ReflectorEvent)
	getProfile func(spiffeID string) *session.BehavioralProfile
	// waitDelivery polls GET /sessions until srcAddr appears. Call immediately
	// after sending events, before querying the profile.
	waitDelivery func(srcAddr string) bool
	teardown     func()
}

func newProfileStack(t *testing.T) *testStack {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sessionMap := session.NewMapWithProfileWindow(60*time.Second, testWindow)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	rpcStream, err := apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	if err != nil {
		cancel()
		_ = conn.Close()
		t.Fatalf("StreamEvents: %v", err)
	}

	apiHandler := session.NewAPI(sessionMap).Handler()

	doGET := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		apiHandler.ServeHTTP(w, req)
		return w
	}

	ts := &testStack{}

	ts.send = func(ev *apiv1.ReflectorEvent) {
		if err := rpcStream.Send(ev); err != nil {
			t.Errorf("Send: %v", err)
		}
	}

	ts.getProfile = func(spiffeID string) *session.BehavioralProfile {
		w := doGET(fmt.Sprintf("/profile?identity=%s", spiffeID))
		if w.Code == http.StatusNotFound {
			return nil
		}
		if w.Code != http.StatusOK {
			t.Fatalf("GET /profile: status %d, body: %s", w.Code, w.Body.String())
		}
		var p session.BehavioralProfile
		if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
			t.Fatalf("decode profile: %v", err)
		}
		return &p
	}

	// waitDelivery polls GET /sessions until srcAddr appears in at least one
	// entry, confirming the event reached the session map. Must be called
	// before getProfile to avoid the window-boundary race.
	ts.waitDelivery = func(srcAddr string) bool {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			w := doGET("/sessions")
			var entries []session.Entry
			if w.Code == http.StatusOK {
				_ = json.NewDecoder(w.Body).Decode(&entries)
			}
			for _, e := range entries {
				if e.SourceAddr == srcAddr {
					return true
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}

	ts.teardown = func() {
		_ = rpcStream.CloseSend()
		cancel()
		_ = conn.Close()
		grpcServer.Stop()
	}
	return ts
}

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

// driveWindow sends n events then sleeps past the window boundary.
func driveWindow(ts *testStack, n int, dst, spiffeID string, pid uint32, srcBase int) {
	for i := range n {
		ts.send(openEvent("node-1", fmt.Sprintf("10.0.0.1:%d", srcBase+i), dst, spiffeID, pid))
	}
	time.Sleep(testWindow + 50*time.Millisecond)
}

// TestBaselineLearningAndNoDeviation verifies that consistent behavior
// produces a low deviation score after baseline warm-up.
func TestBaselineLearningAndNoDeviation(t *testing.T) {
	ts := newProfileStack(t)
	defer ts.teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/w1"
	markerSrc := "10.0.0.1:60000"

	for w := range learnMin + 1 {
		driveWindow(ts, 10, "vault.prod:8200", spiffeID, 1000, 50000+w*10)
	}
	// Send 10 current-window events matching baseline behavior. Wait for the
	// last one to confirm all events are delivered before querying the profile.
	// 10 connections in current window matches baseline avg=10 → score ≈ 0.
	markerSrc = "10.0.0.1:60009"
	for i := range 10 {
		ts.send(openEvent("node-1", fmt.Sprintf("10.0.0.1:%d", 60000+i), "vault.prod:8200", spiffeID, 1000))
	}
	if !ts.waitDelivery(markerSrc) {
		t.Fatal("timed out waiting for current-window events delivery")
	}

	p := ts.getProfile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.Deviation.Score > 0.25 {
		t.Errorf("Deviation.Score = %.3f, want < 0.25 for consistent behavior", p.Deviation.Score)
	}
}

// TestConnectionBurstExceedsDeviationThreshold is the Sprint 12 acceptance test:
// after baseline warm-up, a 10× connection rate burst produces a positive
// deviation score. GET /profile returns score + contributing factors.
func TestConnectionBurstExceedsDeviationThreshold(t *testing.T) {
	ts := newProfileStack(t)
	defer ts.teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/w2"

	for w := range learnMin + 1 {
		driveWindow(ts, 10, "vault.prod:8200", spiffeID, 2000, 51000+w*10)
	}

	// Burst: 100 connections in the current window.
	markerSrc := "10.0.0.1:61099"
	for i := range 100 {
		src := fmt.Sprintf("10.0.0.1:%d", 61000+i)
		ts.send(openEvent("node-1", src, "vault.prod:8200", spiffeID, 2000))
	}
	if !ts.waitDelivery(markerSrc) {
		t.Fatal("timed out waiting for burst events delivery")
	}

	p := ts.getProfile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.Deviation.Score < 0.2 {
		t.Errorf("Deviation.Score = %.3f, want > 0.2 for 10× connection burst", p.Deviation.Score)
	}
	if p.Deviation.ConnectionScore < 0.3 {
		t.Errorf("ConnectionScore = %.3f, want > 0.3", p.Deviation.ConnectionScore)
	}
	if len(p.Deviation.Anomalies) == 0 {
		t.Error("Anomalies is empty, want at least one anomaly flag for burst")
	}
}

// TestNovelDestinationDetected verifies that connecting to a new destination
// not in baseline produces a non-zero destination deviation score.
func TestNovelDestinationDetected(t *testing.T) {
	ts := newProfileStack(t)
	defer ts.teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/w3"

	for w := range learnMin + 1 {
		driveWindow(ts, 5, "vault.prod:8200", spiffeID, 3000, 52000+w*5)
	}

	// Current window: vault (known) + db-prod (novel).
	novelSrc := "10.0.0.1:62001"
	ts.send(openEvent("node-1", "10.0.0.1:62000", "vault.prod:8200", spiffeID, 3000))
	ts.send(openEvent("node-1", novelSrc, "db-prod.internal:5432", spiffeID, 3000))
	if !ts.waitDelivery(novelSrc) {
		t.Fatal("timed out waiting for novel destination event delivery")
	}

	p := ts.getProfile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.Deviation.DestScore == 0 {
		t.Error("DestScore = 0, want > 0 for novel destination")
	}
	if len(p.Deviation.NovelDests) == 0 {
		t.Error("NovelDests is empty, want db-prod.internal:5432")
	}
}

// TestProfileNotFoundForUnseenIdentity verifies HTTP 404 for an identity
// with no observed traffic.
func TestProfileNotFoundForUnseenIdentity(t *testing.T) {
	ts := newProfileStack(t)
	defer ts.teardown()

	p := ts.getProfile("spiffe://prod.example.com/ns/app/sa/unknown")
	if p != nil {
		t.Errorf("expected nil (404) for unseen identity, got profile with SpiffeID=%s", p.SpiffeID)
	}
}

// TestBaselineImmutabilityAfterLock verifies that backdated events cannot
// modify historical windows once profileLearnMin windows are established (RT-008).
func TestBaselineImmutabilityAfterLock(t *testing.T) {
	ts := newProfileStack(t)
	defer ts.teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/w5"

	// Establish baseline: learnMin+1 windows, 5 connections each to vault only.
	for w := range learnMin + 1 {
		driveWindow(ts, 5, "vault.prod:8200", spiffeID, 5000, 64000+w*5)
	}

	// Snapshot baseline profile before the poison attempt.
	markerSrc := "10.0.0.1:64004"
	ts.send(openEvent("node-1", markerSrc, "vault.prod:8200", spiffeID, 5000))
	if !ts.waitDelivery(markerSrc) {
		t.Fatal("timed out waiting for marker delivery")
	}
	before := ts.getProfile(spiffeID)
	if before == nil {
		t.Fatal("expected profile before poison attempt")
	}

	// Inject backdated events claiming evil.corp as a destination in a past window.
	// All timestamps are solidly in the past (well before the current window tail)
	// so the immutability guard must drop all of them.
	// We send enough to flip evil.corp into the majority if the guard isn't working.
	pastBase := time.Now().Add(-time.Duration(learnMin+2) * testWindow)
	for i := range 50 {
		ts.send(&apiv1.ReflectorEvent{
			NodeId:         "node-1",
			Timestamp:      timestamppb.New(pastBase.Add(time.Duration(i) * time.Millisecond)),
			EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
			SourceAddr:     fmt.Sprintf("10.0.0.1:%d", 65000+i),
			DestAddr:       "data-exfil.evil.corp:4444",
			Protocol:       "tcp",
			SourceIdentity: spiffeID,
			IdentityType:   apiv1.ReflectorEvent_SPIFFE,
			Pid:            5000,
		})
	}

	// Send a forward-timestamped marker so we can confirm the stream was flushed.
	markerSrc2 := "10.0.0.1:65999"
	ts.send(openEvent("node-1", markerSrc2, "vault.prod:8200", spiffeID, 5000))
	if !ts.waitDelivery(markerSrc2) {
		t.Fatal("timed out waiting for post-poison marker delivery")
	}

	after := ts.getProfile(spiffeID)
	if after == nil {
		t.Fatal("expected profile after poison attempt")
	}

	// evil.corp must not appear in TypicalDests — backdated events were dropped.
	if after.Baseline.TypicalDests["data-exfil.evil.corp:4444"] {
		t.Error("baseline poisoned: evil.corp in TypicalDests after immutability guard — RT-008 failed")
	}
	// Window count must not have grown from the backdated injections.
	if after.WindowCount > before.WindowCount+1 {
		t.Errorf("WindowCount grew by %d after backdated injection (want ≤ 1 for the forward marker)",
			after.WindowCount-before.WindowCount)
	}
}

// TestProfileWindowHistoryCapped verifies window count stays bounded.
func TestProfileWindowHistoryCapped(t *testing.T) {
	ts := newProfileStack(t)
	defer ts.teardown()

	spiffeID := "spiffe://prod.example.com/ns/app/sa/w4"
	const windowMax = 12 // must match internal session.profileWindowMax

	for w := range windowMax + 3 {
		driveWindow(ts, 5, "vault.prod:8200", spiffeID, 4000, 53000+w*5)
	}
	markerSrc := "10.0.0.1:63004"
	for i := range 5 {
		ts.send(openEvent("node-1", fmt.Sprintf("10.0.0.1:%d", 63000+i), "vault.prod:8200", spiffeID, 4000))
	}
	if !ts.waitDelivery(markerSrc) {
		t.Fatal("timed out waiting for marker event delivery")
	}

	p := ts.getProfile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.WindowCount > windowMax {
		t.Errorf("WindowCount = %d, want <= %d (cap enforced)", p.WindowCount, windowMax)
	}
}
