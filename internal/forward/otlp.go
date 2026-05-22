// Package forward implements non-blocking OTLP signal re-forwarding.
//
// When the reflector captures an OTLP export from SSL_write plaintext,
// this package re-posts the raw protobuf body to a SecOps-controlled
// OTLP collector endpoint. No OTel SDK — the agent already serialized
// the protobuf; we just intercept and replay it. ADR-007.
package forward

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/raygj/workload-ebpf-reflector/internal/extract"
)

// Forwarder re-posts captured OTLP bodies to a configured collector endpoint.
// All operations are non-blocking — errors are returned for the caller to log
// and count, never panicked.
type Forwarder struct {
	endpoint string     // base URL, e.g. "https://collector.example.com"
	client   *http.Client
}

// NewForwarder creates a Forwarder that re-posts OTLP bodies to endpoint.
// endpoint should be the base URL without a trailing slash (e.g. "http://localhost:4318").
func NewForwarder(endpoint string) *Forwarder {
	return &Forwarder{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Forward re-posts the raw protobuf body from sig to the configured OTLP endpoint.
// Returns an error if the signal is truncated, has no body, or the POST fails.
// The caller's traffic is NOT affected — this is fire-and-forget from the agent's perspective.
func (f *Forwarder) Forward(sig *extract.OTLPSignal) error {
	if sig.IsTruncated {
		return fmt.Errorf("skipping truncated %s payload (body incomplete)", sig.SignalType)
	}
	if len(sig.RawBody) == 0 {
		return fmt.Errorf("skipping %s: no raw body to forward", sig.SignalType)
	}

	url := f.endpoint + "/v1/" + sig.SignalType
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(sig.RawBody))
	if err != nil {
		return fmt.Errorf("building OTLP forward request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("OTLP forward POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP forward POST %s: HTTP %d", url, resp.StatusCode)
	}
	return nil
}
