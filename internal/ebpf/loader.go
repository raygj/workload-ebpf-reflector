// Package ebpf loads the reflector eBPF program into the kernel,
// attaches kprobes, and reads connection events from the ring buffer.
//
// Uses cilium/ebpf — pure Go, no CGo (ADR-001).
// Linux only — see loader_stub.go for non-Linux platforms.

//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Loader manages the lifecycle of the eBPF program and its kprobes.
type Loader struct {
	objs   reflectorObjects
	links  []link.Link
	reader *ringbuf.Reader
	logger *slog.Logger
}

// NewLoader creates a Loader but does not yet load the eBPF program.
func NewLoader(logger *slog.Logger) *Loader {
	return &Loader{logger: logger}
}

// Load loads the eBPF program into the kernel and attaches kprobes.
// Call Close() when done to detach and unload.
func (l *Loader) Load(ctx context.Context) error {
	// kernel 5.11+ uses cgroup-based BPF memory accounting, not rlimit.
	// cilium/ebpf's RemoveMemlock calls setrlimit which fails for nonroot
	// users and poisons all subsequent map creation with EPERM.
	// Only call on kernel <5.11 (i.e., root-only legacy path).
	if os.Getuid() == 0 {
		if err := rlimit.RemoveMemlock(); err != nil {
			l.logger.Warn("RemoveMemlock failed", "error", err)
		}
	}
	if err := loadReflectorObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Attach kprobe on tcp_connect (outbound connections)
	kpConnect, err := link.Kprobe("tcp_connect", l.objs.KprobeTcpConnect, nil)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("attaching kprobe/tcp_connect: %w", err)
	}
	l.links = append(l.links, kpConnect)

	// Attach kretprobe on inet_csk_accept (inbound connections)
	krAccept, err := link.Kretprobe("inet_csk_accept", l.objs.KretprobeInetCskAccept, nil)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("attaching kretprobe/inet_csk_accept: %w", err)
	}
	l.links = append(l.links, krAccept)

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("opening ring buffer reader: %w", err)
	}
	l.reader = rd

	// Close the reader when ctx is cancelled so any blocked Read() returns.
	// Started once here — NOT inside Read() to avoid goroutine-per-read leak.
	go func() {
		<-ctx.Done()
		l.reader.Close()
	}()

	l.logger.Info("eBPF program loaded",
		"kprobes", []string{"tcp_connect", "inet_csk_accept"},
	)
	return nil
}

// Read blocks until a raw event is available from the ring buffer,
// or the context is cancelled. Returns the raw bytes of one event.
func (l *Loader) Read(ctx context.Context) ([]byte, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("reading ring buffer: %w", err)
	}
	return record.RawSample, nil
}

// Close detaches kprobes, closes the ring buffer reader, and unloads
// the eBPF program.
func (l *Loader) Close() error {
	if l.reader != nil {
		l.reader.Close()
	}
	l.closeLinks()
	return l.objs.Close()
}

func (l *Loader) closeLinks() {
	for _, ln := range l.links {
		ln.Close()
	}
	l.links = nil
}
