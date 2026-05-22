//go:build linux

package ebpf

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// TCPConn is an active TCP connection belonging to a process.
type TCPConn struct {
	SrcIP   net.IP
	DstIP   net.IP
	DstPort uint16
}

// ConnsByPID returns the active TCP connections (state=ESTABLISHED) for the
// given PID by reading /proc/<pid>/net/tcp. IPv4 only.
func ConnsByPID(pid uint32) ([]TCPConn, error) {
	path := fmt.Sprintf("/proc/%d/net/tcp", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var conns []TCPConn
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Field 3 is the state: 01=ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		src, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		dst, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}
		conns = append(conns, TCPConn{
			SrcIP:   src.IP,
			DstIP:   dst.IP,
			DstPort: uint16(dst.Port),
		})
	}
	return conns, scanner.Err()
}

// parseHexAddr parses a /proc/net/tcp address field "AABBCCDD:PPPP" (hex, little-endian IP).
func parseHexAddr(s string) (*net.TCPAddr, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid addr %q", s)
	}
	ipHex, portHex := parts[0], parts[1]
	if len(ipHex) != 8 {
		return nil, fmt.Errorf("invalid ip hex %q", ipHex)
	}

	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return nil, err
	}
	// /proc/net/tcp stores IP in little-endian u32 — reverse for network order.
	ip := net.IP{raw[3], raw[2], raw[1], raw[0]}

	var port uint16
	if _, err := fmt.Sscanf(portHex, "%X", &port); err != nil {
		return nil, fmt.Errorf("invalid port hex %q: %w", portHex, err)
	}
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}
