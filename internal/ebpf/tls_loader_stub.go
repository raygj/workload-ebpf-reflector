// Stub TLS loader for non-Linux platforms (macOS, Windows).

//go:build !linux

package ebpf

import (
	"context"
	"log/slog"
)

// TLSLoader is a no-op stub on non-Linux platforms.
type TLSLoader struct{}

func NewTLSLoader(_ string, _ *slog.Logger) *TLSLoader { return &TLSLoader{} }

func (l *TLSLoader) Load(_ context.Context) error         { return errNotLinux }
func (l *TLSLoader) Read(_ context.Context) ([]byte, error) { return nil, errNotLinux }
func (l *TLSLoader) Close() error                          { return nil }
