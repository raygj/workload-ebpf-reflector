//go:build linux

package ebpf

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// FlowKey identifies a TCP flow for deny-map lookup.
// Layout must match struct flow_key in tc_drop.c exactly.
type FlowKey struct {
	SrcIP    uint32 // network byte order
	DstIP    uint32 // network byte order
	DstPort  uint16 // network byte order (matches tcp->dest in BPF)
	Protocol uint8
	Pad      uint8
}

// TCLoader attaches the TC drop program to a network interface and manages
// the deny map. Userspace inserts denied flows; the kernel drops them at wire speed.
type TCLoader struct {
	objs   tcDropObjects
	links  []link.Link
	logger *slog.Logger
	iface  string
}

// NewTCLoader creates a TCLoader targeting the given network interface.
func NewTCLoader(iface string, logger *slog.Logger) *TCLoader {
	return &TCLoader{iface: iface, logger: logger}
}

// Load loads the tc_drop eBPF program and attaches it to the interface's
// TC ingress and egress hooks.
func (l *TCLoader) Load() error {
	if err := loadTcDropObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading tc_drop eBPF objects: %w", err)
	}

	iface, err := net.InterfaceByName(l.iface)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("interface %q not found: %w", l.iface, err)
	}

	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.TcDropIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("attaching TC ingress to %s: %w", l.iface, err)
	}
	l.links = append(l.links, ingress)

	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.TcDropEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("attaching TC egress to %s: %w", l.iface, err)
	}
	l.links = append(l.links, egress)

	l.logger.Info("TC drop program loaded", "iface", l.iface)
	return nil
}

// DenyFlow inserts a flow into the deny map. Subsequent packets matching
// {srcIP, dstIP, dstPort/TCP} will be dropped by the TC classifier.
func (l *TCLoader) DenyFlow(srcIP, dstIP net.IP, dstPort uint16) error {
	key := makeFlowKey(srcIP, dstIP, dstPort)
	ts := uint64(time.Now().UnixNano())
	if err := l.objs.DenyMap.Put(key, ts); err != nil {
		return fmt.Errorf("inserting deny flow: %w", err)
	}
	l.logger.Info("flow denied", "src", srcIP, "dst", dstIP, "dst_port", dstPort)
	return nil
}

// AllowFlow removes a flow from the deny map.
func (l *TCLoader) AllowFlow(srcIP, dstIP net.IP, dstPort uint16) error {
	key := makeFlowKey(srcIP, dstIP, dstPort)
	if err := l.objs.DenyMap.Delete(key); err != nil {
		return fmt.Errorf("removing allow flow: %w", err)
	}
	return nil
}

// Close detaches TC hooks, closes links, and unloads the program.
func (l *TCLoader) Close() error {
	l.closeLinks()
	return l.objs.Close()
}

// DefaultIface returns the network interface name used by the default route.
// Falls back to "eth0" if detection fails.
func DefaultIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "eth0"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		// Default route has Destination = 00000000
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return "eth0"
}

func (l *TCLoader) closeLinks() {
	for _, ln := range l.links {
		ln.Close()
	}
	l.links = nil
}

func makeFlowKey(srcIP, dstIP net.IP, dstPort uint16) FlowKey {
	var key FlowKey
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 != nil {
		key.SrcIP = binary.BigEndian.Uint32(src4)
	}
	if dst4 != nil {
		key.DstIP = binary.BigEndian.Uint32(dst4)
	}
	// Store port in network byte order to match tcp->dest in tc_drop.c.
	key.DstPort = dstPort
	key.Protocol = syscall.IPPROTO_TCP
	return key
}
