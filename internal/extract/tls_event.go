package extract

import (
	"encoding/binary"
	"fmt"
	"time"
)

// TLSEventType identifies the direction of captured TLS plaintext.
type TLSEventType uint8

const (
	TLSEventWrite TLSEventType = 0 // SSL_write: outbound plaintext
	TLSEventRead  TLSEventType = 1 // SSL_read: inbound plaintext
)

func (t TLSEventType) String() string {
	switch t {
	case TLSEventWrite:
		return "write"
	case TLSEventRead:
		return "read"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// MaxCaptureBytes matches MAX_CAPTURE_BYTES in tls_hook.c.
// 4096 bytes covers OTLP/HTTP export payloads (1–10 spans) as well as
// JWT Authorization headers and MCP JSON-RPC bodies.
const MaxCaptureBytes = 4096

// TLSDataEventSize is the fixed wire size of a TLS data event from the ring buffer.
// 8 + 4 + 4 + 4 + 4 + 1 + 3 + 4096 = 4124 bytes.
const TLSDataEventSize = 8 + 4 + 4 + 4 + 4 + 1 + 3 + MaxCaptureBytes

// TLSDataEvent is a captured plaintext event from SSL_write or SSL_read.
type TLSDataEvent struct {
	Timestamp   time.Duration // kernel monotonic time
	PID         uint32
	TID         uint32
	Len         uint32 // bytes captured (may be < OriginalLen)
	OriginalLen uint32 // total bytes in the SSL call
	Type        TLSEventType
	Data        []byte // captured plaintext (NOT encrypted)
}

// ParseTLSDataEvent decodes raw bytes from the eBPF ring buffer.
func ParseTLSDataEvent(data []byte) (*TLSDataEvent, error) {
	if len(data) < TLSDataEventSize {
		return nil, fmt.Errorf("TLS event too short: got %d bytes, want %d", len(data), TLSDataEventSize)
	}

	captureLen := binary.LittleEndian.Uint32(data[16:20])
	if captureLen > MaxCaptureBytes {
		captureLen = MaxCaptureBytes
	}

	ev := &TLSDataEvent{
		Timestamp:   time.Duration(binary.LittleEndian.Uint64(data[0:8])) * time.Nanosecond,
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		TID:         binary.LittleEndian.Uint32(data[12:16]),
		Len:         captureLen,
		OriginalLen: binary.LittleEndian.Uint32(data[20:24]),
		Type:        TLSEventType(data[24]),
		Data:        make([]byte, captureLen),
	}
	copy(ev.Data, data[28:28+captureLen])

	return ev, nil
}

// ExtractIdentities runs all identity extractors on the captured plaintext
// and returns whatever it finds: JWT claims, MCP tool calls, OTel signals,
// Boundary session tokens, or nothing.
type IdentityResult struct {
	JWT      *JWTIdentity
	MCP      *MCPToolCall
	OTLP     *OTLPSignal
	Boundary *BoundaryToken
}

// ExtractIdentitiesFromTLS runs all extractors on a TLS data event.
// Extractors are ordered: OTLP first (avoids redundant parsing of non-HTTP paths),
// then JWT, Boundary token, and MCP for non-OTLP HTTP traffic.
// JWT and Boundary are mutually exclusive on the same Authorization header
// (a JWT has dots; a Boundary token does not).
func ExtractIdentitiesFromTLS(ev *TLSDataEvent) *IdentityResult {
	result := &IdentityResult{}

	// OTLP/HTTP or OTLP/gRPC export
	if otlp, err := ExtractOTLPFromTLS(ev.Data); err == nil && otlp != nil {
		result.OTLP = otlp
		return result // OTLP traffic is not JWT/MCP — skip remaining extractors
	}

	// JWT from Authorization header (3-part dot-separated token)
	if jwt, err := ExtractJWTFromHTTP(ev.Data); err == nil && jwt != nil {
		result.JWT = jwt
	}

	// Boundary session/auth token (opaque Bearer token, not a JWT)
	if bt := ExtractBoundaryTokenFromHTTP(ev.Data); bt != nil {
		result.Boundary = bt
	}

	// MCP tool name from JSON-RPC body
	if mcp, err := ExtractMCPToolFromHTTP(ev.Data); err == nil && mcp != nil {
		result.MCP = mcp
	}

	return result
}
