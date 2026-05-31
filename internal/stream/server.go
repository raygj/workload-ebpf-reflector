package stream

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"github.com/raygj/workload-ebpf-reflector/internal/auth"
)

const (
	// DefaultRateLimit is the maximum events per second accepted from a single
	// gRPC stream. Excess events are dropped with ResourceExhausted (RT-004).
	DefaultRateLimit = 5_000
)

// EventHandler is called for each event received from a reflector.
type EventHandler func(*apiv1.ReflectorEvent)

// Server implements the ReflectorService gRPC server (sidecar side).
type Server struct {
	apiv1.UnimplementedReflectorServiceServer
	handler   EventHandler
	rateLimit int // events per second per stream; 0 = unlimited
	logger    *slog.Logger
}

// NewServer creates a stream server that forwards events to the handler.
func NewServer(handler EventHandler, logger *slog.Logger) *Server {
	return &Server{handler: handler, rateLimit: DefaultRateLimit, logger: logger}
}

// NewServerWithRateLimit creates a stream server with a custom per-stream rate limit.
// Set rateLimit to 0 to disable rate limiting (useful in tests).
func NewServerWithRateLimit(handler EventHandler, rateLimit int, logger *slog.Logger) *Server {
	return &Server{handler: handler, rateLimit: rateLimit, logger: logger}
}

// StreamEvents implements the bidirectional stream RPC.
// Reads events from the reflector, forwards to handler.
//
// Per-stream token bucket rate limiting (RT-004): each stream gets its own
// bucket refilled at rateLimit tokens/second. Excess events are rejected
// with gRPC ResourceExhausted — the reflector must back off and retry.
//
// When mTLS is active, node_id is derived from the peer's verified certificate
// (SPIFFE SAN → node_id) rather than the event payload, preventing node ID
// forgery (RT-002, ADR-013).
func (s *Server) StreamEvents(stream apiv1.ReflectorService_StreamEventsServer) error {
	nodeID := nodeIDFromPeer(stream.Context())
	if nodeID != "" {
		s.logger.Info("reflector connected (mTLS)", "node_id", nodeID)
	} else {
		s.logger.Info("reflector connected (unauthenticated)")
	}

	var bucket *tokenBucket
	if s.rateLimit > 0 {
		bucket = newTokenBucket(s.rateLimit)
	}

	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			s.logger.Info("reflector disconnected (EOF)", "node_id", nodeID)
			return nil
		}
		if err != nil {
			s.logger.Error("stream recv error", "error", err)
			return err
		}

		if bucket != nil && !bucket.Allow() {
			return status.Errorf(codes.ResourceExhausted,
				"event rate limit exceeded (%d/s): back off and reconnect", s.rateLimit)
		}

		// Override node_id with the cert-derived value when mTLS is active.
		if nodeID != "" {
			ev.NodeId = nodeID
		}
		s.handler(ev)
	}
}

// nodeIDFromPeer extracts the SPIFFE SAN from the verified peer certificate.
// Returns empty string when mTLS is not active (unauthenticated connections).
func nodeIDFromPeer(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	if id := auth.PeerSPIFFEID(tlsInfo); id != "" {
		return id
	}
	return auth.PeerCN(tlsInfo)
}

// tokenBucket is a simple per-stream token bucket for rate limiting.
// Refills continuously at `rate` tokens/second using a leaky-bucket approach.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	rate     float64 // tokens per second
	max      float64 // burst cap = 2× rate
	lastFill time.Time
}

func newTokenBucket(rate int) *tokenBucket {
	r := float64(rate)
	return &tokenBucket{
		tokens:   r,
		rate:     r,
		max:      r * 2,
		lastFill: time.Now(),
	}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.lastFill = now
	b.tokens = min(b.max, b.tokens+elapsed*b.rate)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
