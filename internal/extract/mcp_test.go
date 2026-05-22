package extract

import (
	"testing"
)

func TestExtractMCPToolFromHTTPToolsCall(t *testing.T) {
	http := "POST /mcp HTTP/1.1\r\nHost: agent.local\r\nContent-Type: application/json\r\n\r\n" +
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vault_read","arguments":{"path":"secret/data/app"}},"id":1}`

	call, err := ExtractMCPToolFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("ExtractMCPToolFromHTTP: %v", err)
	}
	if call == nil {
		t.Fatal("expected MCP tool call, got nil")
	}
	// For tools/call, method should be resolved to params.name
	if call.Method != "vault_read" {
		t.Errorf("Method = %q, want %q", call.Method, "vault_read")
	}
}

func TestExtractMCPToolFromHTTPDirectMethod(t *testing.T) {
	http := "POST /mcp HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" +
		`{"jsonrpc":"2.0","method":"resources/list","id":2}`

	call, err := ExtractMCPToolFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("ExtractMCPToolFromHTTP: %v", err)
	}
	if call == nil {
		t.Fatal("expected MCP tool call, got nil")
	}
	if call.Method != "resources/list" {
		t.Errorf("Method = %q, want %q", call.Method, "resources/list")
	}
}

func TestExtractMCPToolFromHTTPNotJSON(t *testing.T) {
	http := "GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\nplain text body"

	call, err := ExtractMCPToolFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call != nil {
		t.Errorf("expected nil for non-JSON body, got %+v", call)
	}
}

func TestExtractMCPToolFromHTTPNoBody(t *testing.T) {
	http := "GET /health HTTP/1.1\r\nHost: api.example.com"

	call, err := ExtractMCPToolFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call != nil {
		t.Errorf("expected nil for no-body request, got %+v", call)
	}
}

func TestExtractMCPToolFromHTTPNotJSONRPC(t *testing.T) {
	http := "POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" +
		`{"action":"create","resource":"secret"}`

	call, err := ExtractMCPToolFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call != nil {
		t.Errorf("expected nil for non-JSON-RPC body, got %+v", call)
	}
}

func TestParseMCPRequestToolsCallWithName(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"boundary_check_session"},"id":42}`)
	call, err := ParseMCPRequest(body)
	if err != nil {
		t.Fatalf("ParseMCPRequest: %v", err)
	}
	if call.Method != "boundary_check_session" {
		t.Errorf("Method = %q, want %q", call.Method, "boundary_check_session")
	}
}

func TestParseMCPRequestNotification(t *testing.T) {
	// JSON-RPC notification (no id) — should still parse
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	call, err := ParseMCPRequest(body)
	if err != nil {
		t.Fatalf("ParseMCPRequest: %v", err)
	}
	if call == nil {
		t.Fatal("expected call, got nil")
	}
	if call.Method != "notifications/initialized" {
		t.Errorf("Method = %q, want %q", call.Method, "notifications/initialized")
	}
}
