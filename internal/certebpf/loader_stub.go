// Stub for non-Linux platforms. eBPF uprobes require Linux.

//go:build !linux

package certebpf

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

var errNotLinux = errors.New("cert_hook uprobe requires Linux (kernel 5.8+)")

const (
	MaxDERBytes   = 2048
	CertEventSize = 8 + 4 + 4 + 4 + 4 + MaxDERBytes
)

type CertEvent struct {
	Timestamp time.Duration
	PID       uint32
	TID       uint32
	DERLen    uint32
	OrigLen   uint32
	DER       []byte
}

func ParseCertEvent(_ []byte) (*CertEvent, error) { return nil, errNotLinux }

type Loader struct{}

func NewLoader(_ *slog.Logger) *Loader { return &Loader{} }

func (l *Loader) Load(_ string, _ int) error             { return errNotLinux }
func (l *Loader) Read(_ context.Context) ([]byte, error) { return nil, errNotLinux }
func (l *Loader) Close() error                           { return nil }
