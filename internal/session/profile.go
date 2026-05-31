package session

import (
	"math"
	"sync"
	"time"
)

const (
	profileWindowSize = 5 * time.Minute // observation bucket width
	profileWindowMax  = 12              // keep last 12 windows (1 hour history)
	profileLearnMin   = 3               // minimum windows before baseline is meaningful

	// profileDestSetMax caps DestSet entries per window (RT-009).
	// Exceeding this is itself an anomaly signal — tracked via overflow counter.
	profileDestSetMax = 1_000

	// Deviation score weights (must sum to 1.0)
	weightConnectionRate = 0.40
	weightDestNovelty    = 0.40
	weightByteRate       = 0.20
)

// TimeWindow is a fixed-duration observation bucket for a single SPIFFE identity.
type TimeWindow struct {
	Start          time.Time
	End            time.Time
	Connections    int
	DestSet        map[string]int // dest addr → connection count
	ToolSet        map[string]int // MCP tool name → call count
	BytesTx        uint64
	BytesRx        uint64
	DestSetOverflow int // count of destinations dropped due to cap (RT-009)
}

// BaselineStats summarizes historical windows for deviation scoring.
type BaselineStats struct {
	WindowCount       int
	AvgConnections    float64
	StdConnections    float64
	AvgBytesTx        float64
	StdBytesTx        float64
	TypicalDests      map[string]bool // destinations seen in >= half of windows
	TypicalTools      map[string]bool
}

// DeviationReport describes how the current window deviates from baseline.
type DeviationReport struct {
	Score           float64  `json:"score"`            // 0.0 (normal) to 1.0 (extreme anomaly)
	ConnectionScore float64  `json:"connection_score"` // contribution from connection rate
	DestScore       float64  `json:"dest_score"`       // contribution from novel destinations
	ByteScore       float64  `json:"byte_score"`       // contribution from byte rate
	NovelDests      []string `json:"novel_dests"`      // destinations not in baseline
	Anomalies       []string `json:"anomalies"`        // human-readable flags
}

// BehavioralProfile is the full behavioral fingerprint for a SPIFFE identity.
type BehavioralProfile struct {
	SpiffeID      string          `json:"spiffe_id"`
	WindowCount   int             `json:"window_count"`
	CurrentWindow *TimeWindow     `json:"current_window"`
	Baseline      BaselineStats   `json:"baseline"`
	Deviation     DeviationReport `json:"deviation"`
}

// ProfileTracker maintains rolling behavioral profiles per SPIFFE identity.
// Thread-safe. Lives in the session map alongside the rotation tracker.
type ProfileTracker struct {
	mu         sync.Mutex
	windows    map[string][]*TimeWindow // spiffeID → ordered windows (oldest first)
	windowSize time.Duration
}

// NewProfileTracker creates an empty tracker with the default window size.
func NewProfileTracker() *ProfileTracker {
	return newProfileTracker(profileWindowSize)
}

func newProfileTracker(windowSize time.Duration) *ProfileTracker {
	return &ProfileTracker{
		windows:    make(map[string][]*TimeWindow),
		windowSize: windowSize,
	}
}

// Observe records a connection event for the given SPIFFE identity.
// dest and tool may be empty strings if not observed on this event.
//
// Baseline immutability (RT-008): once profileLearnMin windows have been
// established, events with timestamps before the current window's start are
// silently dropped. This prevents backdated event injection from rewriting
// historical windows and poisoning the deviation baseline.
func (p *ProfileTracker) Observe(spiffeID, dest, tool string, bytesTx, bytesRx uint64, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	windows := p.windows[spiffeID]

	// Drop backdated events once baseline is established.
	if len(windows) >= profileLearnMin {
		if last := windows[len(windows)-1]; at.Before(last.Start) {
			return
		}
	}

	cur := p.currentWindow(spiffeID, windows, at)

	cur.Connections++
	if dest != "" {
		if _, exists := cur.DestSet[dest]; exists || len(cur.DestSet) < profileDestSetMax {
			cur.DestSet[dest]++
		} else {
			cur.DestSetOverflow++
		}
	}
	if tool != "" {
		cur.ToolSet[tool]++
	}
	cur.BytesTx += bytesTx
	cur.BytesRx += bytesRx
}

// Profile returns the current behavioral profile and deviation score for a SPIFFE ID.
// Returns nil if no observations have been recorded.
//
// Uses the most recently observed window as "current" rather than advancing to an
// empty wall-clock window. Window advancement is handled exclusively by Observe();
// this prevents a race where crossing a window boundary between delivery confirmation
// and profile query makes the observed burst appear as an empty current window.
func (p *ProfileTracker) Profile(spiffeID string) *BehavioralProfile {
	p.mu.Lock()
	defer p.mu.Unlock()

	windows := p.windows[spiffeID]
	if len(windows) == 0 {
		return nil
	}

	cur := windows[len(windows)-1]
	historical := windows[:len(windows)-1]

	baseline := computeBaseline(historical)
	deviation := computeDeviation(cur, baseline)

	return &BehavioralProfile{
		SpiffeID:      spiffeID,
		WindowCount:   len(windows),
		CurrentWindow: copyWindow(cur),
		Baseline:      baseline,
		Deviation:     deviation,
	}
}

// currentWindow returns the active window for spiffeID at time t,
// creating a new one if the current window has expired. Rolls and caps history.
// Must be called with p.mu held.
func (p *ProfileTracker) currentWindow(spiffeID string, windows []*TimeWindow, t time.Time) *TimeWindow {
	windowStart := t.Truncate(p.windowSize)

	// If there's an active window covering t, return it.
	if len(windows) > 0 {
		last := windows[len(windows)-1]
		if !t.Before(last.Start) && t.Before(last.End) {
			return last
		}
	}

	// Start a new window.
	w := &TimeWindow{
		Start:   windowStart,
		End:     windowStart.Add(p.windowSize),
		DestSet: make(map[string]int),
		ToolSet: make(map[string]int),
	}
	windows = append(windows, w)

	// Cap at profileWindowMax.
	if len(windows) > profileWindowMax {
		windows = windows[len(windows)-profileWindowMax:]
	}
	p.windows[spiffeID] = windows
	return w
}

// copyWindow returns a deep copy of a TimeWindow so callers can read it
// without racing against concurrent Observe() calls on the original.
func copyWindow(w *TimeWindow) *TimeWindow {
	if w == nil {
		return nil
	}
	c := &TimeWindow{
		Start:           w.Start,
		End:             w.End,
		Connections:     w.Connections,
		BytesTx:         w.BytesTx,
		BytesRx:         w.BytesRx,
		DestSetOverflow: w.DestSetOverflow,
		DestSet:         make(map[string]int, len(w.DestSet)),
		ToolSet:         make(map[string]int, len(w.ToolSet)),
	}
	for k, v := range w.DestSet {
		c.DestSet[k] = v
	}
	for k, v := range w.ToolSet {
		c.ToolSet[k] = v
	}
	return c
}

// computeBaseline summarizes a slice of completed windows into baseline stats.
func computeBaseline(windows []*TimeWindow) BaselineStats {
	if len(windows) == 0 {
		return BaselineStats{}
	}

	bs := BaselineStats{
		WindowCount:  len(windows),
		TypicalDests: make(map[string]bool),
		TypicalTools: make(map[string]bool),
	}

	connCounts := make([]float64, len(windows))
	txCounts := make([]float64, len(windows))
	destFreq := make(map[string]int)
	toolFreq := make(map[string]int)

	for i, w := range windows {
		connCounts[i] = float64(w.Connections)
		txCounts[i] = float64(w.BytesTx)
		for d := range w.DestSet {
			destFreq[d]++
		}
		for t := range w.ToolSet {
			toolFreq[t]++
		}
	}

	bs.AvgConnections, bs.StdConnections = meanStd(connCounts)
	bs.AvgBytesTx, bs.StdBytesTx = meanStd(txCounts)

	// Typical = seen in more than half of windows (strict majority).
	threshold := len(windows) / 2
	for d, count := range destFreq {
		if count > threshold {
			bs.TypicalDests[d] = true
		}
	}
	for t, count := range toolFreq {
		if count > threshold {
			bs.TypicalTools[t] = true
		}
	}

	return bs
}

// computeDeviation scores the current window against the baseline.
func computeDeviation(cur *TimeWindow, bs BaselineStats) DeviationReport {
	report := DeviationReport{}

	if bs.WindowCount < profileLearnMin {
		// Not enough history — score is 0, no anomalies declared.
		return report
	}

	// Connection rate z-score → clamped to [0,1].
	connZ := zScore(float64(cur.Connections), bs.AvgConnections, bs.StdConnections)
	report.ConnectionScore = clamp01(connZ / 3.0)

	// Destination novelty: fraction of current dests not in baseline.
	var novelDests []string
	for d := range cur.DestSet {
		if !bs.TypicalDests[d] {
			novelDests = append(novelDests, d)
		}
	}
	report.NovelDests = novelDests
	if len(cur.DestSet) > 0 {
		report.DestScore = clamp01(float64(len(novelDests)) / float64(len(cur.DestSet)))
	}

	// Byte rate z-score.
	byteZ := zScore(float64(cur.BytesTx), bs.AvgBytesTx, bs.StdBytesTx)
	report.ByteScore = clamp01(byteZ / 3.0)

	// Composite score.
	report.Score = weightConnectionRate*report.ConnectionScore +
		weightDestNovelty*report.DestScore +
		weightByteRate*report.ByteScore

	// Human-readable anomaly flags.
	if report.ConnectionScore > 0.5 {
		report.Anomalies = append(report.Anomalies,
			"connection_rate_spike: current rate significantly above baseline")
	}
	if len(novelDests) > 0 {
		report.Anomalies = append(report.Anomalies,
			"novel_destinations: connecting to destinations not in baseline")
	}
	if report.ByteScore > 0.5 {
		report.Anomalies = append(report.Anomalies,
			"byte_rate_spike: data volume significantly above baseline")
	}
	if cur.DestSetOverflow > 0 {
		report.Anomalies = append(report.Anomalies,
			"dest_set_overflow: destination count exceeded cap — possible scanning")
	}

	return report
}

func meanStd(vals []float64) (mean, std float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	for _, v := range vals {
		mean += v
	}
	mean /= float64(len(vals))
	if len(vals) < 2 {
		return mean, 0
	}
	var variance float64
	for _, v := range vals {
		d := v - mean
		variance += d * d
	}
	std = math.Sqrt(variance / float64(len(vals)-1))
	return mean, std
}

func zScore(value, mean, std float64) float64 {
	if std == 0 {
		if value == mean {
			return 0
		}
		return 3.0 // treat any deviation from a zero-std baseline as high
	}
	z := (value - mean) / std
	if z < 0 {
		z = -z // absolute deviation
	}
	return z
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
