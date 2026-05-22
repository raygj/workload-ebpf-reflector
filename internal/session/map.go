// Package session maintains the observation-derived session map.
//
// The session map is a real-time view of every active identity-to-resource
// connection observed by eBPF reflectors. It is NOT a proxy session table —
// it is built entirely from reflector telemetry.
package session

import (
	"sync"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Entry represents a single observed connection in the session map.
type Entry struct {
	NodeID       string    `json:"node_id"`
	SourceAddr   string    `json:"source_addr"`
	DestAddr     string    `json:"dest_addr"`
	Protocol     string    `json:"protocol"`
	Identity     string    `json:"identity,omitempty"`
	IdentityType string    `json:"identity_type,omitempty"`
	MCPTool      string    `json:"mcp_tool,omitempty"`
	PID          uint32    `json:"pid,omitempty"`
	BytesTx      uint64    `json:"bytes_tx"`
	BytesRx      uint64    `json:"bytes_rx"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"` // "active", "closed", "stale"

	// OTel export fields (populated when identity_type == "otel")
	OTELService    string `json:"otel_service,omitempty"`
	OTELSignalType string `json:"otel_signal_type,omitempty"` // "traces", "metrics", "logs"
	OTELSpanCount  uint32 `json:"otel_span_count,omitempty"`

	// Boundary session correlation (populated when a Boundary token is observed)
	BoundarySessionToken string `json:"boundary_session_token,omitempty"`
	BoundaryTokenType    string `json:"boundary_token_type,omitempty"` // "auth", "session", "opaque"

	// Cert rotation fields (populated when status == "rotation_*")
	CertSerial            string    `json:"cert_serial,omitempty"`
	CertExpiry            time.Time `json:"cert_expiry,omitempty"`
	CertIssuerFingerprint string    `json:"cert_issuer_fingerprint,omitempty"`
	PrevCertSerial        string    `json:"prev_cert_serial,omitempty"`
}

// connectionKey uniquely identifies a connection for map lookups.
func connectionKey(nodeID, srcAddr, dstAddr, protocol string) string {
	return nodeID + "|" + srcAddr + "|" + dstAddr + "|" + protocol
}

// Map is a thread-safe, observation-derived session map.
type Map struct {
	mu       sync.RWMutex
	entries  map[string]*Entry // keyed by connectionKey
	staleTTL time.Duration
	rotation *RotationTracker
	profiles *ProfileTracker
}

// NewMap creates an empty session map with the given stale TTL.
func NewMap(staleTTL time.Duration) *Map {
	return &Map{
		entries:  make(map[string]*Entry),
		staleTTL: staleTTL,
		rotation: NewRotationTracker(),
		profiles: NewProfileTracker(),
	}
}

// GetProfile returns the behavioral profile for a SPIFFE identity, or nil if unknown.
func (m *Map) GetProfile(spiffeID string) *BehavioralProfile {
	return m.profiles.Profile(spiffeID, time.Now())
}

// HandleEvent processes a ReflectorEvent and updates the session map.
func (m *Map) HandleEvent(ev *apiv1.ReflectorEvent) {
	if ev.EventType == apiv1.ReflectorEvent_STREAM_RESUMED {
		m.markStaleFromNode(ev.NodeId)
		return
	}

	key := connectionKey(ev.NodeId, ev.SourceAddr, ev.DestAddr, ev.Protocol)
	now := time.Now()
	if ev.Timestamp != nil {
		now = ev.Timestamp.AsTime()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch ev.EventType {
	case apiv1.ReflectorEvent_CONNECTION_OPEN:
		identity, idType := pickIdentity(ev)
		e := &Entry{
			NodeID:       ev.NodeId,
			SourceAddr:   ev.SourceAddr,
			DestAddr:     ev.DestAddr,
			Protocol:     ev.Protocol,
			Identity:     identity,
			IdentityType: idType,
			MCPTool:      ev.McpToolName,
			PID:          ev.Pid,
			BytesTx:      ev.BytesTx,
			BytesRx:      ev.BytesRx,
			FirstSeen:    now,
			LastSeen:     now,
			Status:       "active",
		}
		applyOTELFields(e, ev)
		if ev.BoundarySessionToken != "" {
			e.BoundarySessionToken = ev.BoundarySessionToken
			e.BoundaryTokenType = ev.BoundaryTokenType
		}
		m.entries[key] = e
		// Feed behavioral profile on connection open for SPIFFE identities
		if identity != "" && idType == "spiffe" {
			m.mu.Unlock()
			m.profiles.Observe(identity, ev.DestAddr, ev.McpToolName, ev.BytesTx, ev.BytesRx, now)
			m.mu.Lock()
		}

	case apiv1.ReflectorEvent_CONNECTION_CLOSE:
		if entry, ok := m.entries[key]; ok {
			entry.Status = "closed"
			entry.LastSeen = now
			entry.BytesTx = ev.BytesTx
			entry.BytesRx = ev.BytesRx
		}

	case apiv1.ReflectorEvent_DATA_EXCHANGE:
		if entry, ok := m.entries[key]; ok {
			entry.LastSeen = now
			entry.BytesTx = ev.BytesTx
			entry.BytesRx = ev.BytesRx
			// Update identity if newly discovered
			if entry.Identity == "" {
				identity, idType := pickIdentity(ev)
				entry.Identity = identity
				entry.IdentityType = idType
			}
			if entry.MCPTool == "" && ev.McpToolName != "" {
				entry.MCPTool = ev.McpToolName
			}
			// Update OTel fields on DATA_EXCHANGE (each export is a new observation)
			applyOTELFields(entry, ev)
			// Track cert rotation if cert metadata is present
			if ev.IdentityType == apiv1.ReflectorEvent_SPIFFE && ev.CertSerial != "" {
				m.trackCertRotation(ev, now)
			}
			// Capture Boundary session token if observed
			if ev.BoundarySessionToken != "" && entry.BoundarySessionToken == "" {
				entry.BoundarySessionToken = ev.BoundarySessionToken
				entry.BoundaryTokenType = ev.BoundaryTokenType
			}
			// Feed behavioral profile for SPIFFE-identified sessions
			if entry.Identity != "" {
				m.mu.Unlock()
				m.profiles.Observe(entry.Identity, entry.DestAddr, entry.MCPTool,
					ev.BytesTx, ev.BytesRx, now)
				m.mu.Lock()
			}
		}

	case apiv1.ReflectorEvent_CERT_ROTATION_NORMAL,
		apiv1.ReflectorEvent_CERT_ROTATION_EARLY,
		apiv1.ReflectorEvent_CERT_ROTATION_ISSUER,
		apiv1.ReflectorEvent_CERT_ROTATION_DOMAIN:
		// Rotation events are stored as synthetic entries keyed by SPIFFE ID + timestamp.
		// They are queryable via GET /sessions?status=rotation_* and serve as an audit trail.
		rotStatus := rotationEventStatus(ev.EventType)
		expiry := time.Time{}
		if ev.CertExpiry != nil {
			expiry = ev.CertExpiry.AsTime()
		}
		e := &Entry{
			NodeID:                ev.NodeId,
			SourceAddr:            ev.SourceAddr,
			DestAddr:              ev.DestAddr,
			Protocol:              ev.Protocol,
			Identity:              ev.SourceIdentity,
			IdentityType:          "spiffe",
			PID:                   ev.Pid,
			FirstSeen:             now,
			LastSeen:              now,
			Status:                rotStatus,
			CertSerial:            ev.CertSerial,
			CertExpiry:            expiry,
			CertIssuerFingerprint: ev.CertIssuerFingerprint,
			PrevCertSerial:        ev.PrevCertSerial,
		}
		m.entries[key] = e
	}
}

// trackCertRotation classifies a SPIFFE cert observation and, if it's a rotation,
// synthesizes a CERT_ROTATION_* entry in the map. Must be called with m.mu held.
func (m *Map) trackCertRotation(ev *apiv1.ReflectorEvent, now time.Time) {
	expiry := time.Time{}
	if ev.CertExpiry != nil {
		expiry = ev.CertExpiry.AsTime()
	}
	obs := CertObservation{
		Serial:            ev.CertSerial,
		Expiry:            expiry,
		IssuerFingerprint: ev.CertIssuerFingerprint,
		TrustDomain:       trustDomainFromSPIFFE(ev.SourceIdentity),
		ObservedAt:        now,
	}

	// Unlock to call Track (which has its own lock), then re-lock.
	m.mu.Unlock()
	class := m.rotation.Track(ev.SourceIdentity, obs)
	m.mu.Lock()

	if class == RotationFirstSeen {
		return // first observation — nothing to record
	}

	evType := rotationClassToEventType(class)
	rotStatus := rotationEventStatus(evType)

	// Synthetic key: SPIFFE ID + timestamp — guaranteed unique per rotation event.
	syntheticKey := ev.SourceIdentity + "|rotation|" + now.Format(time.RFC3339Nano)
	m.entries[syntheticKey] = &Entry{
		NodeID:                ev.NodeId,
		SourceAddr:            ev.SourceAddr,
		DestAddr:              ev.DestAddr,
		Protocol:              ev.Protocol,
		Identity:              ev.SourceIdentity,
		IdentityType:          "spiffe",
		PID:                   ev.Pid,
		FirstSeen:             now,
		LastSeen:              now,
		Status:                rotStatus,
		CertSerial:            ev.CertSerial,
		CertExpiry:            expiry,
		CertIssuerFingerprint: ev.CertIssuerFingerprint,
	}
}

func rotationEventStatus(evType apiv1.ReflectorEvent_EventType) string {
	switch evType {
	case apiv1.ReflectorEvent_CERT_ROTATION_NORMAL:
		return "rotation_normal"
	case apiv1.ReflectorEvent_CERT_ROTATION_EARLY:
		return "rotation_early"
	case apiv1.ReflectorEvent_CERT_ROTATION_ISSUER:
		return "rotation_issuer"
	case apiv1.ReflectorEvent_CERT_ROTATION_DOMAIN:
		return "rotation_domain"
	default:
		return "rotation_unknown"
	}
}

func rotationClassToEventType(class RotationClass) apiv1.ReflectorEvent_EventType {
	switch class {
	case RotationEarly:
		return apiv1.ReflectorEvent_CERT_ROTATION_EARLY
	case RotationIssuerChange:
		return apiv1.ReflectorEvent_CERT_ROTATION_ISSUER
	case RotationDomainChange:
		return apiv1.ReflectorEvent_CERT_ROTATION_DOMAIN
	default:
		return apiv1.ReflectorEvent_CERT_ROTATION_NORMAL
	}
}

func trustDomainFromSPIFFE(spiffeID string) string {
	// spiffe://trust-domain/path → "trust-domain"
	const prefix = "spiffe://"
	if len(spiffeID) <= len(prefix) {
		return spiffeID
	}
	rest := spiffeID[len(prefix):]
	for i, c := range rest {
		if c == '/' {
			return rest[:i]
		}
	}
	return rest
}

// AttestationTTL is the maximum age of a session entry for attestation purposes.
// Entries older than this are treated as unknown (confidence: jwt-only).
const AttestationTTL = 5 * time.Minute

// AttestResult is the response from a Lookup call.
type AttestResult struct {
	SpiffeID   string    `json:"spiffe_id"`
	ObservedAt time.Time `json:"observed_at"`
	// Confidence is "kernel" if the reflector observed the cert at the TLS layer,
	// "jwt-only" if the connection was not found or the observation is too old.
	Confidence string `json:"confidence"`
}

// Lookup finds the most recent entry matching the given PID, src, and dst addresses.
// Returns an AttestResult with confidence "kernel" if a valid kernel-observed entry
// is found, or "jwt-only" if not found or too old. Never returns an error —
// callers should fail open on attestation unavailability.
func (m *Map) Lookup(pid uint32, srcAddr, dstAddr string) AttestResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cutoff := time.Now().Add(-AttestationTTL)
	var best *Entry
	for _, e := range m.entries {
		if e.SourceAddr != srcAddr || e.DestAddr != dstAddr {
			continue
		}
		if pid != 0 && e.PID != pid {
			continue
		}
		if e.LastSeen.Before(cutoff) {
			continue
		}
		if best == nil || e.LastSeen.After(best.LastSeen) {
			best = e
		}
	}

	if best == nil || best.Identity == "" {
		return AttestResult{Confidence: "jwt-only"}
	}
	return AttestResult{
		SpiffeID:   best.Identity,
		ObservedAt: best.LastSeen,
		Confidence: "kernel",
	}
}

// QueryAll returns all entries matching the given filters.
// Empty filter values match everything.
func (m *Map) QueryAll(identity, dest, status string) []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []Entry
	for _, e := range m.entries {
		if identity != "" && e.Identity != identity {
			continue
		}
		if dest != "" && e.DestAddr != dest {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		results = append(results, *e)
	}
	return results
}

// Stats returns summary counts.
type Stats struct {
	Active     int `json:"active"`
	Closed     int `json:"closed"`
	Stale      int `json:"stale"`
	Identities int `json:"distinct_identities"`
}

// GetStats returns current session map statistics.
func (m *Map) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var s Stats
	identities := make(map[string]bool)
	for _, e := range m.entries {
		switch e.Status {
		case "active":
			s.Active++
		case "closed":
			s.Closed++
		case "stale":
			s.Stale++
		}
		if e.Identity != "" {
			identities[e.Identity] = true
		}
	}
	s.Identities = len(identities)
	return s
}

// Sweep marks entries as stale if not updated within staleTTL,
// removes closed entries older than staleTTL, and removes stale entries
// older than 2×staleTTL. Call periodically.
func (m *Map) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-m.staleTTL)
	staleCutoff := now.Add(-2 * m.staleTTL)
	for key, e := range m.entries {
		switch e.Status {
		case "closed":
			if e.LastSeen.Before(cutoff) {
				delete(m.entries, key)
			}
		case "stale":
			if e.LastSeen.Before(staleCutoff) {
				delete(m.entries, key)
			}
		case "active":
			if e.LastSeen.Before(cutoff) {
				e.Status = "stale"
			}
		}
	}
}

// markStaleFromNode marks all active entries from a node as stale
// (called on STREAM_RESUMED to indicate a gap in observation).
func (m *Map) markStaleFromNode(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range m.entries {
		if e.NodeID == nodeID && e.Status == "active" {
			e.Status = "stale"
		}
	}
}

func pickIdentity(ev *apiv1.ReflectorEvent) (string, string) {
	if ev.IdentityType == apiv1.ReflectorEvent_OTEL && ev.OtelService != "" {
		return ev.OtelService, "otel"
	}
	if ev.SourceIdentity != "" {
		switch ev.IdentityType {
		case apiv1.ReflectorEvent_SPIFFE:
			return ev.SourceIdentity, "spiffe"
		case apiv1.ReflectorEvent_JWT:
			return ev.SourceIdentity, "jwt"
		case apiv1.ReflectorEvent_MCP:
			return ev.SourceIdentity, "mcp"
		default:
			return ev.SourceIdentity, "unknown"
		}
	}
	return "", ""
}

// applyOTELFields populates OTel-specific fields on an Entry from a ReflectorEvent.
func applyOTELFields(e *Entry, ev *apiv1.ReflectorEvent) {
	if ev.IdentityType != apiv1.ReflectorEvent_OTEL {
		return
	}
	if ev.OtelService != "" {
		e.OTELService = ev.OtelService
	}
	if ev.OtelSignalType != "" {
		e.OTELSignalType = ev.OtelSignalType
	}
	if ev.OtelSpanCount > 0 {
		e.OTELSpanCount = ev.OtelSpanCount
	}
}

// NewTestEvent is a helper for building test events.
func NewTestEvent(nodeID, src, dst, proto, identity string, evType apiv1.ReflectorEvent_EventType) *apiv1.ReflectorEvent {
	return &apiv1.ReflectorEvent{
		NodeId:         nodeID,
		Timestamp:      timestamppb.Now(),
		EventType:      evType,
		SourceAddr:     src,
		DestAddr:       dst,
		Protocol:       proto,
		SourceIdentity: identity,
		IdentityType:   apiv1.ReflectorEvent_SPIFFE,
	}
}
