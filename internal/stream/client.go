// Package stream implements the gRPC metadata stream between the
// eBPF reflector and the reflector-map sidecar (ADR-003).
package stream

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Client streams ReflectorEvents to the reflector-map sidecar.
type Client struct {
	addr   string
	nodeID string
	logger *slog.Logger
	conn   *grpc.ClientConn
	stream apiv1.ReflectorService_StreamEventsClient
}

// NewClient creates a stream client targeting the sidecar at addr.
func NewClient(addr, nodeID string, logger *slog.Logger) *Client {
	return &Client{addr: addr, nodeID: nodeID, logger: logger}
}

// Connect establishes the gRPC connection and opens the bidirectional stream.
func (c *Client) Connect(ctx context.Context) error {
	conn, err := grpc.NewClient(c.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                120 * time.Second,
			Timeout:             20 * time.Second,
			PermitWithoutStream: false,
		}),
	)
	if err != nil {
		return fmt.Errorf("connecting to sidecar at %s: %w", c.addr, err)
	}
	c.conn = conn

	client := apiv1.NewReflectorServiceClient(conn)
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("opening stream: %w", err)
	}
	c.stream = stream

	c.logger.Info("stream connected", "sidecar", c.addr, "node_id", c.nodeID)
	return nil
}

// Send sends a single event to the sidecar. Returns an error if the
// stream is broken (caller should reconnect).
func (c *Client) Send(ev *apiv1.ReflectorEvent) error {
	if c.stream == nil {
		return fmt.Errorf("stream not connected")
	}
	ev.NodeId = c.nodeID
	return c.stream.Send(ev)
}

// SendResumed sends a STREAM_RESUMED sentinel after reconnection
// so the sidecar can mark a gap in its session map.
func (c *Client) SendResumed() error {
	return c.Send(&apiv1.ReflectorEvent{
		EventType: apiv1.ReflectorEvent_STREAM_RESUMED,
	})
}

// Close shuts down the stream and connection.
func (c *Client) Close() error {
	if c.stream != nil {
		_ = c.stream.CloseSend()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
