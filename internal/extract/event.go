// Package extract parses identity metadata from raw eBPF ring buffer events.
//
// Sprint 1 (crawl): 5-tuple extraction (src/dst IP, src/dst port, protocol).
// Sprint 2: SPIFFE ID, JWT claims, MCP tool name.
package extract

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// EventType identifies whether a connection was initiated or accepted.
type EventType uint8

const (
	EventConnect EventType = 0 // Outbound TCP connection (client)
	EventAccept  EventType = 1 // Inbound TCP connection (server)
)

func (t EventType) String() string {
	switch t {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// AddressFamily identifies IPv4 vs IPv6.
type AddressFamily uint8

const (
	AFInet  AddressFamily = 2  // AF_INET
	AFInet6 AddressFamily = 10 // AF_INET6
)

// RawEvent is the wire format matching the eBPF struct event (packed).
// Total size: 8+4+4+4+4+2+2+1+1+1+1+16+16 = 64 bytes.
type RawEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	SrcAddr     uint32     // IPv4 source, network byte order
	DstAddr     uint32     // IPv4 dest, network byte order
	SrcPort     uint16     // source port, host byte order
	DstPort     uint16     // dest port, host byte order
	Protocol    uint8      // IPPROTO_TCP = 6
	EventType   uint8      // 0=connect, 1=accept
	AF          uint8      // AF_INET=2, AF_INET6=10
	Pad         uint8      //nolint:unused
	SrcAddr6    [16]uint8  // IPv6 source
	DstAddr6    [16]uint8  // IPv6 dest
}

// RawEventSize is the expected byte size of a RawEvent from the ring buffer.
const RawEventSize = 64

// ConnectionEvent is the parsed, Go-native representation of a connection.
type ConnectionEvent struct {
	Timestamp time.Duration // monotonic kernel time since boot
	PID       uint32
	TID       uint32
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Type      EventType
	Family    AddressFamily
}

// ParseEvent decodes raw bytes from the eBPF ring buffer into a ConnectionEvent.
func ParseEvent(data []byte) (*ConnectionEvent, error) {
	if len(data) < RawEventSize {
		return nil, fmt.Errorf("event too short: got %d bytes, want %d", len(data), RawEventSize)
	}

	raw := RawEvent{
		TimestampNS: binary.LittleEndian.Uint64(data[0:8]),
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		TID:         binary.LittleEndian.Uint32(data[12:16]),
		SrcAddr:     binary.LittleEndian.Uint32(data[16:20]),
		DstAddr:     binary.LittleEndian.Uint32(data[20:24]),
		SrcPort:     binary.LittleEndian.Uint16(data[24:26]),
		DstPort:     binary.LittleEndian.Uint16(data[26:28]),
		Protocol:    data[28],
		EventType:   data[29],
		AF:          data[30],
	}
	copy(raw.SrcAddr6[:], data[32:48])
	copy(raw.DstAddr6[:], data[48:64])

	ev := &ConnectionEvent{
		Timestamp: time.Duration(raw.TimestampNS) * time.Nanosecond,
		PID:       raw.PID,
		TID:       raw.TID,
		SrcPort:   raw.SrcPort,
		DstPort:   raw.DstPort,
		Protocol:  raw.Protocol,
		Type:      EventType(raw.EventType),
		Family:    AddressFamily(raw.AF),
	}

	switch ev.Family {
	case AFInet:
		ev.SrcIP = uint32ToIPv4(raw.SrcAddr)
		ev.DstIP = uint32ToIPv4(raw.DstAddr)
	case AFInet6:
		ev.SrcIP = net.IP(raw.SrcAddr6[:])
		ev.DstIP = net.IP(raw.DstAddr6[:])
	default:
		return nil, fmt.Errorf("unsupported address family: %d", raw.AF)
	}

	return ev, nil
}

// FiveTuple returns the connection's 5-tuple as a formatted string.
func (e *ConnectionEvent) FiveTuple() string {
	return fmt.Sprintf("%s:%d -> %s:%d proto=%d",
		e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Protocol)
}

// uint32ToIPv4 converts a uint32 in network byte order to net.IP.
// The kernel stores IPv4 addresses in network byte order (big-endian),
// but we read them as little-endian uint32 from the packed struct,
// so the bytes are already in the right order for net.IP.
func uint32ToIPv4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	// addr was read as little-endian from packed struct bytes,
	// but the original bytes are network order (big-endian).
	// We write it back as little-endian to recover the original bytes.
	binary.LittleEndian.PutUint32(ip, addr)
	return ip
}
