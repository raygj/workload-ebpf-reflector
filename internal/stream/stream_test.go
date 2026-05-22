package stream

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStreamClientServerIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Collect events received by the server
	var mu sync.Mutex
	var received []*apiv1.ReflectorEvent

	handler := func(ev *apiv1.ReflectorEvent) {
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
	}

	// Start gRPC server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	srv := NewServer(handler, logger)
	apiv1.RegisterReflectorServiceServer(grpcServer, srv)

	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	// Connect client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewClient(lis.Addr().String(), "test-node", logger)
	// Use direct connection for test
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client.conn = conn

	rpcClient := apiv1.NewReflectorServiceClient(conn)
	stream, err := rpcClient.StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client.stream = stream

	// Send events
	events := []*apiv1.ReflectorEvent{
		{
			NodeId:         "test-node",
			Timestamp:      timestamppb.Now(),
			EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
			SourceAddr:     "10.0.0.1:5000",
			DestAddr:       "vault.prod:8200",
			Protocol:       "tcp",
			SourceIdentity: "spiffe://prod/agent/deploy",
			IdentityType:   apiv1.ReflectorEvent_SPIFFE,
		},
		{
			NodeId:         "test-node",
			Timestamp:      timestamppb.Now(),
			EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
			SourceAddr:     "10.0.0.1:5001",
			DestAddr:       "kafka.prod:9092",
			Protocol:       "tcp",
			SourceIdentity: "spiffe://prod/agent/deploy",
			IdentityType:   apiv1.ReflectorEvent_SPIFFE,
			McpToolName:    "vault_read",
		},
		{
			NodeId:    "test-node",
			Timestamp: timestamppb.Now(),
			EventType: apiv1.ReflectorEvent_CONNECTION_CLOSE,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "vault.prod:8200",
			Protocol:   "tcp",
		},
	}

	for _, ev := range events {
		if err := stream.Send(ev); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	// Close send side and wait for server to process
	_ = stream.CloseSend()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 3 {
		t.Fatalf("expected 3 events received, got %d", len(received))
	}
	if received[0].SourceIdentity != "spiffe://prod/agent/deploy" {
		t.Errorf("event[0] identity = %q, want spiffe://prod/agent/deploy", received[0].SourceIdentity)
	}
	if received[1].McpToolName != "vault_read" {
		t.Errorf("event[1] mcp_tool = %q, want vault_read", received[1].McpToolName)
	}
	if received[2].EventType != apiv1.ReflectorEvent_CONNECTION_CLOSE {
		t.Errorf("event[2] type = %v, want CONNECTION_CLOSE", received[2].EventType)
	}
}
