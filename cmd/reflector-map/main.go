// Package main is the entry point for the reflector-map sidecar.
//
// reflector-map receives the metadata stream from eBPF reflectors via
// bidirectional gRPC, maintains an observation-derived session map, and
// exposes it via HTTP API for querying.
//
// ADR-003: Boundary has no inbound telemetry API. This sidecar owns
// the session map until Boundary adds native non-proxied session awareness.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"github.com/raygj/workload-ebpf-reflector/internal/auth"
	"github.com/raygj/workload-ebpf-reflector/internal/metrics"
	"github.com/raygj/workload-ebpf-reflector/internal/session"
	"github.com/raygj/workload-ebpf-reflector/internal/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func main() {
	grpcAddr := flag.String("grpc-addr", ":9100", "gRPC listen address for reflector streams")
	httpAddr := flag.String("http-addr", ":9101", "HTTP listen address for session map API")
	metricsAddr := flag.String("metrics-addr", ":9091", "HTTP listen address for /healthz and /metrics")
	staleTTL := flag.Duration("stale-ttl", 60*time.Second, "TTL before active entries become stale")
	tlsCA := flag.String("tls-ca", "", "PEM CA cert for gRPC mTLS (ADR-013); if unset, gRPC runs insecure")
	tlsCert := flag.String("tls-cert", "", "PEM server cert for gRPC mTLS")
	tlsKey := flag.String("tls-key", "", "PEM server key for gRPC mTLS")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	startTime := time.Now()

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()

	// Prometheus metrics
	metrics.RegisterSidecar(prometheus.DefaultRegisterer)

	// Session map
	sessionMap := session.NewMap(*staleTTL)

	// Event handler: update session map + metrics
	handler := func(ev *apiv1.ReflectorEvent) {
		metrics.StreamEventsReceivedTotal.Inc()
		sessionMap.HandleEvent(ev)
		stats := sessionMap.GetStats()
		metrics.SessionMapActiveConnections.Set(float64(stats.Active))
		metrics.SessionMapIdentitiesActive.Set(float64(stats.Identities))
	}

	// Periodic sweep of stale/closed entries
	go func() {
		ticker := time.NewTicker(*staleTTL / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sessionMap.Sweep()
				stats := sessionMap.GetStats()
				metrics.SessionMapActiveConnections.Set(float64(stats.Active))
				metrics.SessionMapIdentitiesActive.Set(float64(stats.Identities))
			case <-ctx.Done():
				return
			}
		}
	}()

	// gRPC server for reflector streams
	tlsCfg := auth.TLSConfig{CACertFile: *tlsCA, CertFile: *tlsCert, KeyFile: *tlsKey}
	grpcOpts := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             60 * time.Second,
			PermitWithoutStream: false,
		}),
	}
	if tlsCfg.Enabled() {
		creds, err := tlsCfg.ServerCredentials()
		if err != nil {
			logger.Error("gRPC mTLS setup failed", "error", err)
			os.Exit(1)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		logger.Info("gRPC mTLS enabled — client cert required")
	} else {
		grpcOpts = append(grpcOpts, grpc.Creds(insecure.NewCredentials()))
		logger.Warn("gRPC running without mTLS — set --tls-ca/cert/key for authenticated transport (ADR-013)")
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	streamServer := stream.NewServer(handler, logger)
	apiv1.RegisterReflectorServiceServer(grpcServer, streamServer)

	grpcLis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		logger.Error("gRPC listen failed", "addr", *grpcAddr, "error", err)
		os.Exit(1)
	}
	go func() {
		logger.Info("gRPC server listening", "addr", grpcLis.Addr().String())
		if err := grpcServer.Serve(grpcLis); err != nil {
			logger.Error("gRPC server error", "error", err)
		}
	}()

	// HTTP API for session map queries
	api := session.NewAPI(sessionMap)
	httpServer := &http.Server{
		Addr:    *httpAddr,
		Handler: auth.TokenMiddleware(api.Handler(), logger),
	}
	go func() {
		logger.Info("HTTP API listening", "addr", *httpAddr,
			"endpoints", []string{"GET /sessions", "GET /stats"},
		)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("HTTP API error", "error", err)
		}
	}()

	// Metrics + health endpoint
	metricsServer := &http.Server{
		Addr:    *metricsAddr,
		Handler: metrics.NewHTTPHandler("reflector-map", startTime),
	}
	go func() {
		logger.Info("metrics server listening", "addr", *metricsAddr,
			"endpoints", []string{"GET /healthz", "GET /metrics"},
		)
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("metrics server error", "error", err)
		}
	}()

	logger.Info("reflector-map sidecar started",
		"grpc", *grpcAddr,
		"http", *httpAddr,
		"metrics", *metricsAddr,
		"stale_ttl", staleTTL.String(),
	)

	<-ctx.Done()
	logger.Info("shutting down")

	grpcServer.GracefulStop()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	_ = metricsServer.Shutdown(shutdownCtx)

	stats := sessionMap.GetStats()
	fmt.Fprintf(os.Stderr, "final stats: %+v\n", stats)
}
