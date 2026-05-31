package session

import (
	"encoding/json"
	"net/http"
	"strconv"
)

const defaultSessionsLimit = 1_000

// API exposes the session map over HTTP for querying.
//
// Endpoints:
//
//	GET /sessions              — all entries (filterable via query params)
//	GET /sessions?identity=X   — filter by source identity
//	GET /sessions?dest=X       — filter by destination address
//	GET /sessions?status=X     — filter by status (active, closed, stale)
//	GET /stats                 — summary counts
type API struct {
	sessionMap *Map
}

// NewAPI creates an HTTP API backed by the given session map.
func NewAPI(m *Map) *API {
	return &API{sessionMap: m}
}

// Handler returns an http.Handler with all routes registered.
// Only GET is accepted; all other methods return 405 Method Not Allowed.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sessions", a.handleSessions)
	mux.HandleFunc("GET /stats", a.handleStats)
	mux.HandleFunc("GET /attest", a.handleAttest)
	mux.HandleFunc("GET /profile", a.handleProfile)
	// Catch-all: reject non-GET methods on any registered path.
	mux.HandleFunc("/sessions", methodNotAllowed)
	mux.HandleFunc("/stats", methodNotAllowed)
	mux.HandleFunc("/attest", methodNotAllowed)
	mux.HandleFunc("/profile", methodNotAllowed)
	return mux
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "GET")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (a *API) handleSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	identity := q.Get("identity")
	dest := q.Get("dest")
	status := q.Get("status")
	nodeID := q.Get("node_id")

	limit := defaultSessionsLimit
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = n
	}
	offset := 0
	if s := q.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
		offset = n
	}

	entries := a.sessionMap.QueryAll(identity, dest, status, nodeID)
	if entries == nil {
		entries = []Entry{}
	}

	// Apply pagination.
	if offset >= len(entries) {
		entries = []Entry{}
	} else {
		entries = entries[offset:]
		if len(entries) > limit {
			entries = entries[:limit]
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := a.sessionMap.GetStats()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleAttest answers the question: "What SPIFFE ID did the kernel observe for this connection?"
//
// GET /attest?pid=<pid>&src=<ip:port>&dst=<ip:port>
//
// Always returns HTTP 200. Fails open: if the connection is unknown or too old,
// returns confidence "jwt-only" rather than an error. Callers must never reject
// a request solely because the reflector returned jwt-only — the reflector may
// have restarted or the cert observation may not yet have arrived.
func (a *API) handleAttest(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pidStr := q.Get("pid")
	src := q.Get("src")
	dst := q.Get("dst")

	var pid uint64
	if pidStr != "" {
		var err error
		pid, err = strconv.ParseUint(pidStr, 10, 32)
		if err != nil || pid == 0 {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}
	}

	result := a.sessionMap.Lookup(uint32(pid), src, dst)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleProfile returns the behavioral profile and deviation score for a SPIFFE identity.
//
// GET /profile?identity=<spiffe_id>
//
// Returns HTTP 404 if the identity has not been observed.
// Returns HTTP 200 with the profile including current window, baseline stats,
// deviation score (0.0=normal, 1.0=extreme anomaly), and anomaly flags.
func (a *API) handleProfile(w http.ResponseWriter, r *http.Request) {
	identity := r.URL.Query().Get("identity")
	if identity == "" {
		http.Error(w, "identity parameter required", http.StatusBadRequest)
		return
	}

	profile := a.sessionMap.GetProfile(identity)
	if profile == nil {
		http.Error(w, "identity not observed", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
