package extract

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func buildTLSDataEvent(timestampNS uint64, pid, tid, captureLen, originalLen uint32, eventType uint8, payload []byte) []byte {
	buf := make([]byte, TLSDataEventSize)
	binary.LittleEndian.PutUint64(buf[0:8], timestampNS)
	binary.LittleEndian.PutUint32(buf[8:12], pid)
	binary.LittleEndian.PutUint32(buf[12:16], tid)
	binary.LittleEndian.PutUint32(buf[16:20], captureLen)
	binary.LittleEndian.PutUint32(buf[20:24], originalLen)
	buf[24] = eventType
	// pad: buf[25:28] = 0
	copy(buf[28:], payload)
	return buf
}

func TestParseTLSDataEvent(t *testing.T) {
	payload := []byte("GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n")
	data := buildTLSDataEvent(1_000_000_000, 100, 100, uint32(len(payload)), uint32(len(payload)), 0, payload)

	ev, err := ParseTLSDataEvent(data)
	if err != nil {
		t.Fatalf("ParseTLSDataEvent: %v", err)
	}
	if ev.PID != 100 {
		t.Errorf("PID = %d, want 100", ev.PID)
	}
	if ev.Type != TLSEventWrite {
		t.Errorf("Type = %v, want write", ev.Type)
	}
	if ev.Len != uint32(len(payload)) {
		t.Errorf("Len = %d, want %d", ev.Len, len(payload))
	}
	if string(ev.Data) != string(payload) {
		t.Errorf("Data = %q, want %q", string(ev.Data), string(payload))
	}
}

func TestParseTLSDataEventTooShort(t *testing.T) {
	_, err := ParseTLSDataEvent(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short data, got nil")
	}
}

func TestExtractIdentitiesFromTLSWithJWT(t *testing.T) {
	token := buildJWT(`{"sub":"spiffe://prod/agent/scanner","iss":"vault"}`)
	payload := fmt.Appendf(nil, "POST /api/scan HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n{}", token)

	ev := &TLSDataEvent{
		PID:  42,
		Type: TLSEventWrite,
		Len:  uint32(len(payload)),
		Data: payload,
	}

	result := ExtractIdentitiesFromTLS(ev)
	if result.JWT == nil {
		t.Fatal("expected JWT identity, got nil")
	}
	if result.JWT.Subject != "spiffe://prod/agent/scanner" {
		t.Errorf("JWT.Subject = %q, want %q", result.JWT.Subject, "spiffe://prod/agent/scanner")
	}
}

func TestExtractIdentitiesFromTLSWithMCP(t *testing.T) {
	payload := []byte("POST /mcp HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" +
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vault_read"},"id":1}`)

	ev := &TLSDataEvent{
		PID:  42,
		Type: TLSEventWrite,
		Len:  uint32(len(payload)),
		Data: payload,
	}

	result := ExtractIdentitiesFromTLS(ev)
	if result.MCP == nil {
		t.Fatal("expected MCP tool call, got nil")
	}
	if result.MCP.Method != "vault_read" {
		t.Errorf("MCP.Method = %q, want %q", result.MCP.Method, "vault_read")
	}
}

func TestExtractIdentitiesFromTLSWithBoth(t *testing.T) {
	token := buildJWT(`{"sub":"agent-42"}`)
	payload := fmt.Appendf(nil,
		"POST /mcp HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n\r\n"+
			`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret_rotate"},"id":5}`,
		token,
	)

	ev := &TLSDataEvent{
		PID:  42,
		Type: TLSEventWrite,
		Len:  uint32(len(payload)),
		Data: payload,
	}

	result := ExtractIdentitiesFromTLS(ev)
	if result.JWT == nil {
		t.Fatal("expected JWT, got nil")
	}
	if result.MCP == nil {
		t.Fatal("expected MCP, got nil")
	}
	if result.JWT.Subject != "agent-42" {
		t.Errorf("JWT.Subject = %q, want %q", result.JWT.Subject, "agent-42")
	}
	if result.MCP.Method != "secret_rotate" {
		t.Errorf("MCP.Method = %q, want %q", result.MCP.Method, "secret_rotate")
	}
}
