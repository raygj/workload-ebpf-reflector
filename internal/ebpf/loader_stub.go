// Stub loader for non-Linux platforms (macOS, Windows).
// The eBPF reflector only runs on Linux — this stub lets the binary compile
// everywhere with a clear error at runtime.

//go:build !linux

package ebpf

import (
	"context"
	"errors"
	"log/slog"
)

var errNotLinux = errors.New("eBPF reflector requires Linux (kernel 5.8+, BTF enabled)")

type Loader struct{}

func NewLoader(_ *slog.Logger) *Loader { return &Loader{} }

func (l *Loader) Load(_ context.Context) error        { return errNotLinux }
func (l *Loader) Read(_ context.Context) ([]byte, error) { return nil, errNotLinux }
func (l *Loader) Close() error                         { return nil }
