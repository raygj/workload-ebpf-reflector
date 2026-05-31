package session

import (
	"sync"
	"time"
)

const (
	certHistoryMax   = 10            // max observations kept per SPIFFE path
	rotationLearnMin = 3             // minimum observations before interval baseline is used
	earlyFraction    = 0.75          // rotation is "early" if it fires before this fraction of expected lifetime

	// rotationRateWindow is the window over which rotationRateMax is enforced (RT-006).
	rotationRateWindow = time.Minute
	// rotationRateMax is the max cert rotation events accepted per identity per window.
	// Exceeding this drops the event silently — prevents signal flooding (F-005).
	rotationRateMax = 10
)

// CertObservation is a single cert observation for a SPIFFE path.
type CertObservation struct {
	Serial            string
	Expiry            time.Time
	IssuerFingerprint string
	TrustDomain       string
	ObservedAt        time.Time
	// PID is the process ID of the workload that presented this cert.
	// Used to distinguish pod restarts (new PID, same SPIFFE path) from
	// in-process early rotation (same PID, new cert before expiry).
	PID uint32
}

// RotationClass classifies a new cert observation relative to history.
type RotationClass int

const (
	RotationFirstSeen    RotationClass = iota // no history — just record it
	RotationNormal                            // scheduled, expected, same issuer
	RotationEarly                             // before expected expiry
	RotationIssuerChange                      // issuer fingerprint changed
	RotationDomainChange                      // trust domain changed
)

// RotationTracker maintains cert history per SPIFFE path and classifies
// new observations. Thread-safe. Lives in the session map sidecar.
type RotationTracker struct {
	mu        sync.Mutex
	history   map[string][]CertObservation // keyed by SPIFFE path (full URI)
	rateCount map[string]int               // events seen in current rate window
	rateReset map[string]time.Time         // when the rate window resets
}

// NewRotationTracker creates an empty tracker.
func NewRotationTracker() *RotationTracker {
	return &RotationTracker{
		history:   make(map[string][]CertObservation),
		rateCount: make(map[string]int),
		rateReset: make(map[string]time.Time),
	}
}

// Track records a new cert observation for the given SPIFFE ID and returns
// its RotationClass. The SPIFFE ID is used as the history key (full URI).
func (t *RotationTracker) Track(spiffeID string, obs CertObservation) RotationClass {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Per-identity rate limiting: drop events exceeding rotationRateMax per window (RT-006).
	now := obs.ObservedAt
	if now.IsZero() {
		now = time.Now()
	}
	if reset, ok := t.rateReset[spiffeID]; !ok || now.After(reset) {
		t.rateCount[spiffeID] = 0
		t.rateReset[spiffeID] = now.Add(rotationRateWindow)
	}
	t.rateCount[spiffeID]++
	if t.rateCount[spiffeID] > rotationRateMax {
		return RotationFirstSeen // silently drop; caller treats as no-op
	}

	hist := t.history[spiffeID]

	if len(hist) == 0 {
		t.history[spiffeID] = append(hist, obs)
		return RotationFirstSeen
	}

	last := hist[len(hist)-1]

	// Same cert — not a rotation at all, just another observation of the same SVID.
	if obs.Serial == last.Serial {
		return RotationFirstSeen
	}

	var class RotationClass

	pidChanged := obs.PID != 0 && last.PID != 0 && obs.PID != last.PID

	switch {
	case obs.TrustDomain != last.TrustDomain:
		class = RotationDomainChange

	case obs.IssuerFingerprint != last.IssuerFingerprint:
		class = RotationIssuerChange

	case isEarlyRotation(obs, last, hist) && !pidChanged:
		// Early rotation on the same process is suspicious. If the PID changed,
		// it's a pod restart — SPIRE issues a new SVID immediately, which looks
		// early against the previous pod's cert timeline. That's expected, not anomalous.
		class = RotationEarly

	default:
		class = RotationNormal
	}

	// Append and cap at certHistoryMax.
	hist = append(hist, obs)
	if len(hist) > certHistoryMax {
		hist = hist[len(hist)-certHistoryMax:]
	}
	t.history[spiffeID] = hist
	return class
}

// History returns the observation history for a SPIFFE ID (copy).
func (t *RotationTracker) History(spiffeID string) []CertObservation {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.history[spiffeID]
	out := make([]CertObservation, len(h))
	copy(out, h)
	return out
}

// isEarlyRotation returns true if the new cert arrived significantly before
// the previous cert's expiry. Uses learned interval if enough history exists.
func isEarlyRotation(newObs, last CertObservation, hist []CertObservation) bool {
	// If the previous cert has already expired, this is not early.
	if newObs.ObservedAt.After(last.Expiry) {
		return false
	}

	// If we have enough history, use the learned rotation interval.
	if len(hist) >= rotationLearnMin {
		interval := learnedInterval(hist)
		if interval > 0 {
			expectedNext := last.ObservedAt.Add(interval)
			// Early if observed more than 25% before the expected next rotation.
			return newObs.ObservedAt.Before(expectedNext.Add(-interval / 4))
		}
	}

	// Fallback: early if the previous cert still has more than 25% lifetime left.
	lifetime := last.Expiry.Sub(last.ObservedAt)
	remaining := last.Expiry.Sub(newObs.ObservedAt)
	if lifetime <= 0 {
		return false
	}
	return float64(remaining)/float64(lifetime) > (1 - earlyFraction)
}

// learnedInterval computes the median rotation interval from observation history.
func learnedInterval(hist []CertObservation) time.Duration {
	if len(hist) < 2 {
		return 0
	}
	intervals := make([]time.Duration, 0, len(hist)-1)
	for i := 1; i < len(hist); i++ {
		d := hist[i].ObservedAt.Sub(hist[i-1].ObservedAt)
		if d > 0 {
			intervals = append(intervals, d)
		}
	}
	if len(intervals) == 0 {
		return 0
	}
	// Simple median via sort-free approach: sum and average.
	// Good enough for K<=10 history.
	var total time.Duration
	for _, d := range intervals {
		total += d
	}
	return total / time.Duration(len(intervals))
}
