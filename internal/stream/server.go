package stream

import (
	"io"
	"log/slog"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
)

// EventHandler is called for each event received from a reflector.
type EventHandler func(*apiv1.ReflectorEvent)

// Server implements the ReflectorService gRPC server (sidecar side).
type Server struct {
	apiv1.UnimplementedReflectorServiceServer
	handler EventHandler
	logger  *slog.Logger
}

// NewServer creates a stream server that forwards events to the handler.
func NewServer(handler EventHandler, logger *slog.Logger) *Server {
	return &Server{handler: handler, logger: logger}
}

// StreamEvents implements the bidirectional stream RPC.
// Reads events from the reflector, forwards to handler.
// In crawl, the sidecar→reflector direction (WorkerCommand) is unused.
func (s *Server) StreamEvents(stream apiv1.ReflectorService_StreamEventsServer) error {
	s.logger.Info("reflector connected")

	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			s.logger.Info("reflector disconnected (EOF)")
			return nil
		}
		if err != nil {
			s.logger.Error("stream recv error", "error", err)
			return err
		}
		s.handler(ev)
	}
}
