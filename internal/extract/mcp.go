package extract

import (
	"encoding/json"
)

// MCPToolCall represents an MCP tool invocation extracted from a JSON-RPC request.
type MCPToolCall struct {
	Method string `json:"method"`
	ID     any    `json:"id,omitempty"`
}

// ExtractMCPToolFromHTTP scans captured HTTP plaintext for an MCP JSON-RPC
// request body and extracts the tool (method) name.
// Returns nil if no MCP tool call is found.
//
// MCP uses JSON-RPC 2.0 over HTTP. Tool calls look like:
//
//	{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vault_read",...},"id":1}
//
// We extract the top-level "method" field. For tools/call, we also extract
// params.name as the actual tool name.
func ExtractMCPToolFromHTTP(plaintext []byte) (*MCPToolCall, error) {
	body := findHTTPBody(plaintext)
	if body == nil {
		return nil, nil
	}
	return ParseMCPRequest(body)
}

// ParseMCPRequest parses a JSON-RPC request body and extracts the method name.
func ParseMCPRequest(body []byte) (*MCPToolCall, error) {
	var msg struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		ID      any    `json:"id"`
		Params  *struct {
			Name string `json:"name"`
		} `json:"params"`
	}

	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, nil // Not valid JSON — not an MCP request, not an error
	}

	if msg.JSONRPC != "2.0" || msg.Method == "" {
		return nil, nil // Not a JSON-RPC 2.0 request
	}

	call := &MCPToolCall{
		Method: msg.Method,
		ID:     msg.ID,
	}

	// For tools/call, the actual tool name is in params.name
	if msg.Method == "tools/call" && msg.Params != nil && msg.Params.Name != "" {
		call.Method = msg.Params.Name
	}

	return call, nil
}

// findHTTPBody returns the body portion of an HTTP request (after \r\n\r\n).
func findHTTPBody(data []byte) []byte {
	for i := 0; i+3 < len(data); i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return data[i+4:]
		}
	}
	// Try \n\n as fallback
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return data[i+2:]
		}
	}
	return nil
}
