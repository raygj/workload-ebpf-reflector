package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProfileTrackerFirstObservationNoDeviation(t *testing.T) {
	tr := NewProfileTracker()
	now := time.Now()

	tr.Observe("spiffe://prod/agent/deploy", "vault:8200", "secrets/read", 1024, 512, now)

	p := tr.Profile("spiffe://prod/agent/deploy")
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.CurrentWindow.Connections != 1 {
		t.Errorf("Connections = %d, want 1", p.CurrentWindow.Connections)
	}
	// Not enough history for baseline — score must be 0
	if p.Deviation.Score != 0 {
		t.Errorf("Score = %.2f, want 0.0 (insufficient baseline)", p.Deviation.Score)
	}
}

func TestProfileTrackerUnknownIdentityReturnsNil(t *testing.T) {
	tr := NewProfileTracker()
	p := tr.Profile("spiffe://prod/unknown/identity")
	if p != nil {
		t.Errorf("expected nil for unseen identity, got %+v", p)
	}
}

func TestProfileTrackerNormalBehaviorLowDeviation(t *testing.T) {
	tr := NewProfileTracker()
	spiffeID := "spiffe://prod/agent/deploy"

	// Build baseline: profileLearnMin+1 windows of consistent behavior
	base := time.Now().Truncate(profileWindowSize)
	for w := range profileLearnMin + 1 {
		windowStart := base.Add(time.Duration(w) * profileWindowSize)
		for c := range 10 {
			tr.Observe(spiffeID, "vault:8200", "secrets/read", 1000, 500,
				windowStart.Add(time.Duration(c)*30*time.Second))
		}
	}

	// Current window — same behavior as baseline
	currentStart := base.Add(time.Duration(profileLearnMin+1) * profileWindowSize)
	for c := range 10 {
		tr.Observe(spiffeID, "vault:8200", "secrets/read", 1000, 500,
			currentStart.Add(time.Duration(c)*30*time.Second))
	}

	p := tr.Profile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.Deviation.Score > 0.1 {
		t.Errorf("Score = %.2f, want < 0.1 for normal behavior", p.Deviation.Score)
	}
}

func TestProfileTrackerConnectionSpike(t *testing.T) {
	tr := NewProfileTracker()
	spiffeID := "spiffe://prod/agent/deploy"

	// Build baseline: consistent 10 connections per window
	base := time.Now().Truncate(profileWindowSize)
	for w := range profileLearnMin + 1 {
		windowStart := base.Add(time.Duration(w) * profileWindowSize)
		for c := range 10 {
			tr.Observe(spiffeID, "vault:8200", "", 0, 0,
				windowStart.Add(time.Duration(c)*30*time.Second))
		}
	}

	// Current window — 200 connections (20× baseline)
	currentStart := base.Add(time.Duration(profileLearnMin+1) * profileWindowSize)
	for c := range 200 {
		tr.Observe(spiffeID, "vault:8200", "", 0, 0,
			currentStart.Add(time.Duration(c)*time.Second))
	}

	p := tr.Profile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.Deviation.Score < 0.3 {
		t.Errorf("Score = %.2f, want > 0.3 for connection spike", p.Deviation.Score)
	}
	if p.Deviation.ConnectionScore < 0.3 {
		t.Errorf("ConnectionScore = %.2f, want > 0.3", p.Deviation.ConnectionScore)
	}
}

func TestProfileTrackerNovelDestination(t *testing.T) {
	tr := NewProfileTracker()
	spiffeID := "spiffe://prod/agent/deploy"

	// Baseline: always connects to vault:8200
	base := time.Now().Truncate(profileWindowSize)
	for w := range profileLearnMin + 1 {
		windowStart := base.Add(time.Duration(w) * profileWindowSize)
		for c := range 5 {
			tr.Observe(spiffeID, "vault:8200", "", 0, 0,
				windowStart.Add(time.Duration(c)*60*time.Second))
		}
	}

	// Current window — connects to a new destination never seen before
	currentStart := base.Add(time.Duration(profileLearnMin+1) * profileWindowSize)
	tr.Observe(spiffeID, "vault:8200", "", 0, 0, currentStart)
	tr.Observe(spiffeID, "db-prod.internal:5432", "", 0, 0, currentStart.Add(time.Minute))

	p := tr.Profile(spiffeID)
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
	if p.Deviation.DestScore == 0 {
		t.Error("DestScore = 0, want > 0 for novel destination")
	}
	if len(p.Deviation.NovelDests) == 0 {
		t.Error("expected NovelDests to contain db-prod.internal:5432")
	}
}

func TestProfileTrackerWindowHistoryCapped(t *testing.T) {
	tr := NewProfileTracker()
	spiffeID := "spiffe://prod/agent/deploy"

	base := time.Now().Truncate(profileWindowSize)
	for w := range profileWindowMax + 5 {
		windowStart := base.Add(time.Duration(w) * profileWindowSize)
		tr.Observe(spiffeID, "vault:8200", "", 0, 0, windowStart)
	}

	tr.mu.Lock()
	count := len(tr.windows[spiffeID])
	tr.mu.Unlock()

	if count > profileWindowMax {
		t.Errorf("window count = %d, want <= %d", count, profileWindowMax)
	}
}

func TestProfileAPIEndpoint(t *testing.T) {
	// Integration: session map → profile tracker → GET /profile
	m := NewMap(30 * time.Second)
	api := NewAPI(m)

	// /profile for unknown identity → 404
	req := httptest.NewRequest(http.MethodGet, "/profile?identity=spiffe://prod/unknown", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("status = %d, want 404 for unknown identity", w.Code)
	}

	// /profile missing identity param → 400
	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	w = httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d, want 400 for missing identity", w.Code)
	}
}
