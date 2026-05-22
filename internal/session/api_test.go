package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
)

func setupAPITest() (*API, *Map) {
	m := NewMap(30 * time.Second)
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "vault.prod:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.5:6000", "vault.prod:8200", "tcp",
		"spiffe://prod/agent/scan", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5001", "kafka.prod:9092", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	return NewAPI(m), m
}

func TestAPIGetAllSessions(t *testing.T) {
	api, _ := setupAPITest()
	req := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var entries []Entry
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestAPIFilterByIdentity(t *testing.T) {
	api, _ := setupAPITest()
	req := httptest.NewRequest("GET", "/sessions?identity=spiffe://prod/agent/deploy", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var entries []Entry
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for agent/deploy, got %d", len(entries))
	}
}

func TestAPIFilterByDest(t *testing.T) {
	api, _ := setupAPITest()
	req := httptest.NewRequest("GET", "/sessions?dest=vault.prod:8200", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var entries []Entry
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for vault.prod:8200, got %d", len(entries))
	}
}

func TestAPIStats(t *testing.T) {
	api, _ := setupAPITest()
	req := httptest.NewRequest("GET", "/stats", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var stats Stats
	_ = json.NewDecoder(w.Body).Decode(&stats)
	if stats.Active != 3 {
		t.Errorf("Active = %d, want 3", stats.Active)
	}
	if stats.Identities != 2 {
		t.Errorf("Identities = %d, want 2", stats.Identities)
	}
}

func TestAPIAttestKernelConfidence(t *testing.T) {
	m := NewMap(30 * time.Second)
	ev := NewTestEvent("node-1", "10.0.0.1:50001", "vault.prod:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN)
	ev.Pid = 4242
	m.HandleEvent(ev)

	api := NewAPI(m)
	req := httptest.NewRequest("GET", "/attest?pid=4242&src=10.0.0.1:50001&dst=vault.prod:8200", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var result AttestResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Confidence != "kernel" {
		t.Errorf("Confidence = %q, want kernel", result.Confidence)
	}
	if result.SpiffeID != "spiffe://prod/agent/deploy" {
		t.Errorf("SpiffeID = %q, want spiffe://prod/agent/deploy", result.SpiffeID)
	}
}

func TestAPIAttestMissReturnsJWTOnly(t *testing.T) {
	api := NewAPI(NewMap(30 * time.Second))
	req := httptest.NewRequest("GET", "/attest?pid=9999&src=10.0.0.99:50099&dst=vault.prod:8200", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
	var result AttestResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Confidence != "jwt-only" {
		t.Errorf("Confidence = %q, want jwt-only", result.Confidence)
	}
}

func TestAPIAttestExpiredReturnsJWTOnly(t *testing.T) {
	m := NewMap(30 * time.Second)
	ev := NewTestEvent("node-1", "10.0.0.1:50002", "vault.prod:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN)
	ev.Pid = 1111
	// Back-date the event to beyond AttestationTTL
	ev.Timestamp = nil
	m.HandleEvent(ev)

	// Manually age the entry
	m.mu.Lock()
	for _, e := range m.entries {
		if e.SourceAddr == "10.0.0.1:50002" {
			e.LastSeen = e.LastSeen.Add(-(AttestationTTL + time.Second))
		}
	}
	m.mu.Unlock()

	api := NewAPI(m)
	req := httptest.NewRequest("GET", "/attest?pid=1111&src=10.0.0.1:50002&dst=vault.prod:8200", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var result AttestResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Confidence != "jwt-only" {
		t.Errorf("Confidence = %q, want jwt-only for expired entry", result.Confidence)
	}
}

func TestAPIEmptyResult(t *testing.T) {
	api := NewAPI(NewMap(30 * time.Second))
	req := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var entries []Entry
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
