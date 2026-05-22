package extract

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildRawEvent constructs raw bytes matching the eBPF struct event layout.
func buildRawEvent(
	timestampNS uint64,
	pid, tid uint32,
	srcAddr, dstAddr uint32,
	srcPort, dstPort uint16,
	protocol, eventType, af uint8,
	srcAddr6, dstAddr6 [16]byte,
) []byte {
	buf := make([]byte, RawEventSize)
	binary.LittleEndian.PutUint64(buf[0:8], timestampNS)
	binary.LittleEndian.PutUint32(buf[8:12], pid)
	binary.LittleEndian.PutUint32(buf[12:16], tid)
	binary.LittleEndian.PutUint32(buf[16:20], srcAddr)
	binary.LittleEndian.PutUint32(buf[20:24], dstAddr)
	binary.LittleEndian.PutUint16(buf[24:26], srcPort)
	binary.LittleEndian.PutUint16(buf[26:28], dstPort)
	buf[28] = protocol
	buf[29] = eventType
	buf[30] = af
	buf[31] = 0 // pad
	copy(buf[32:48], srcAddr6[:])
	copy(buf[48:64], dstAddr6[:])
	return buf
}

func TestParseEventIPv4Connect(t *testing.T) {
	// Simulate: PID 1234 connecting from 10.0.0.1:5000 to 10.0.0.2:8200
	srcAddr := ipv4ToUint32LE(net.ParseIP("10.0.0.1").To4())
	dstAddr := ipv4ToUint32LE(net.ParseIP("10.0.0.2").To4())

	data := buildRawEvent(
		1_000_000_000, // 1 second
		1234, 1234,
		srcAddr, dstAddr,
		5000, 8200,
		6, // TCP
		0, // connect
		2, // AF_INET
		[16]byte{}, [16]byte{},
	)

	ev, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}

	if ev.PID != 1234 {
		t.Errorf("PID = %d, want 1234", ev.PID)
	}
	if ev.Type != EventConnect {
		t.Errorf("Type = %v, want connect", ev.Type)
	}
	if ev.Family != AFInet {
		t.Errorf("Family = %d, want AF_INET(2)", ev.Family)
	}
	if !ev.SrcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("SrcIP = %v, want 10.0.0.1", ev.SrcIP)
	}
	if !ev.DstIP.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("DstIP = %v, want 10.0.0.2", ev.DstIP)
	}
	if ev.SrcPort != 5000 {
		t.Errorf("SrcPort = %d, want 5000", ev.SrcPort)
	}
	if ev.DstPort != 8200 {
		t.Errorf("DstPort = %d, want 8200", ev.DstPort)
	}
	if ev.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", ev.Protocol)
	}
	if ev.Timestamp != time.Second {
		t.Errorf("Timestamp = %v, want 1s", ev.Timestamp)
	}
}

func TestParseEventIPv4Accept(t *testing.T) {
	// Simulate: PID 5678 accepting connection from 192.168.1.100:45000 on port 443
	srcAddr := ipv4ToUint32LE(net.ParseIP("192.168.1.100").To4())
	dstAddr := ipv4ToUint32LE(net.ParseIP("192.168.1.1").To4())

	data := buildRawEvent(
		2_500_000_000,
		5678, 5678,
		srcAddr, dstAddr,
		45000, 443,
		6, 1, 2, // TCP, accept, AF_INET
		[16]byte{}, [16]byte{},
	)

	ev, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}

	if ev.Type != EventAccept {
		t.Errorf("Type = %v, want accept", ev.Type)
	}
	if !ev.SrcIP.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("SrcIP = %v, want 192.168.1.100", ev.SrcIP)
	}
	if !ev.DstIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("DstIP = %v, want 192.168.1.1", ev.DstIP)
	}
}

func TestParseEventIPv6(t *testing.T) {
	// Simulate: IPv6 connect from fd00::1 to fd00::2
	src6 := net.ParseIP("fd00::1")
	dst6 := net.ParseIP("fd00::2")
	var srcArr, dstArr [16]byte
	copy(srcArr[:], src6.To16())
	copy(dstArr[:], dst6.To16())

	data := buildRawEvent(
		500_000_000,
		42, 42,
		0, 0, // IPv4 fields unused
		8080, 9090,
		6, 0, 10, // TCP, connect, AF_INET6
		srcArr, dstArr,
	)

	ev, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}

	if ev.Family != AFInet6 {
		t.Errorf("Family = %d, want AF_INET6(10)", ev.Family)
	}
	if !ev.SrcIP.Equal(src6) {
		t.Errorf("SrcIP = %v, want fd00::1", ev.SrcIP)
	}
	if !ev.DstIP.Equal(dst6) {
		t.Errorf("DstIP = %v, want fd00::2", ev.DstIP)
	}
}

func TestParseEventTooShort(t *testing.T) {
	_, err := ParseEvent(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short data, got nil")
	}
}

func TestParseEventUnsupportedFamily(t *testing.T) {
	data := buildRawEvent(0, 0, 0, 0, 0, 0, 0, 6, 0, 99, [16]byte{}, [16]byte{})
	_, err := ParseEvent(data)
	if err == nil {
		t.Error("expected error for unsupported address family, got nil")
	}
}

func TestFiveTupleFormat(t *testing.T) {
	ev := &ConnectionEvent{
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
		SrcPort:  5000,
		DstPort:  8200,
		Protocol: 6,
	}
	want := "10.0.0.1:5000 -> 10.0.0.2:8200 proto=6"
	if got := ev.FiveTuple(); got != want {
		t.Errorf("FiveTuple() = %q, want %q", got, want)
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		t    EventType
		want string
	}{
		{EventConnect, "connect"},
		{EventAccept, "accept"},
		{EventType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

// ipv4ToUint32LE converts a 4-byte IPv4 to uint32 in little-endian encoding,
// matching how binary.LittleEndian.Uint32 reads the packed struct bytes.
func ipv4ToUint32LE(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip[:4])
}
