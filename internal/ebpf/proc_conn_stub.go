//go:build !linux

package ebpf

import "net"

type TCPConn struct {
	SrcIP   net.IP
	DstIP   net.IP
	DstPort uint16
}

func ConnsByPID(_ uint32) ([]TCPConn, error) { return nil, nil }
