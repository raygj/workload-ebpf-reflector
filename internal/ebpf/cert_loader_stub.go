//go:build !linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
)

type CertEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	DERLen      uint32
	OrigLen     uint32
	DER         []byte
}

func ParseCertEvent(_ []byte) (*CertEvent, error) {
	return nil, fmt.Errorf("not supported on this platform")
}

type CertLoader struct{}

func NewCertLoader(_ string, _ *slog.Logger) *CertLoader { return &CertLoader{} }

func (l *CertLoader) Load(_ context.Context) error { return fmt.Errorf("eBPF not supported on this platform") }

func (l *CertLoader) Read(_ context.Context) ([]byte, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func (l *CertLoader) AttachToExecutable(_ string) error { return nil }

func (l *CertLoader) AttachedCount() int { return 0 }

func (l *CertLoader) Close() error { return nil }
