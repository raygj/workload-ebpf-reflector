//go:build !linux

package ebpf

import (
	"fmt"
	"log/slog"
	"net"
)

type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	DstPort  uint16
	Protocol uint8
	Pad      uint8
}

type TCLoader struct{}

func NewTCLoader(_ string, _ *slog.Logger) *TCLoader { return &TCLoader{} }

func DefaultIface() string { return "eth0" }

func (l *TCLoader) Load() error                                    { return fmt.Errorf("TC eBPF not supported on this platform") }
func (l *TCLoader) DenyFlow(_, _ net.IP, _ uint16) error           { return nil }
func (l *TCLoader) AllowFlow(_, _ net.IP, _ uint16) error          { return nil }
func (l *TCLoader) Close() error                                   { return nil }
