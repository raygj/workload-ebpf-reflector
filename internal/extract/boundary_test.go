package extract

import (
	"fmt"
	"testing"
)

func TestExtractBoundaryAuthToken(t *testing.T) {
	token := "at_c0nfYh1ts4ecret00000000000000000000"
	http := fmt.Sprintf("POST /v1/targets/list HTTP/1.1\r\nHost: boundary.prod:9200\r\nAuthorization: Bearer %s\r\n\r\n", token)

	bt := ExtractBoundaryTokenFromHTTP([]byte(http))
	if bt == nil {
		t.Fatal("expected Boundary token, got nil")
	}
	if bt.TokenType != BoundaryTokenAuth {
		t.Errorf("TokenType = %q, want %q", bt.TokenType, BoundaryTokenAuth)
	}
	if bt.Raw != token {
		t.Errorf("Raw = %q, want %q", bt.Raw, token)
	}
}

func TestExtractBoundarySessionToken(t *testing.T) {
	token := "s_abcdef1234567890abcdef1234567890"
	http := fmt.Sprintf("POST /v1/sessions HTTP/1.1\r\nHost: boundary.prod:9200\r\nAuthorization: Bearer %s\r\n\r\n", token)

	bt := ExtractBoundaryTokenFromHTTP([]byte(http))
	if bt == nil {
		t.Fatal("expected Boundary token, got nil")
	}
	if bt.TokenType != BoundaryTokenSession {
		t.Errorf("TokenType = %q, want %q", bt.TokenType, BoundaryTokenSession)
	}
}

func TestExtractBoundaryOpaqueUUID(t *testing.T) {
	token := "550e8400-e29b-41d4-a716-446655440000"
	http := fmt.Sprintf("POST /v1/connect HTTP/1.1\r\nHost: boundary.prod:9200\r\nAuthorization: Bearer %s\r\n\r\n", token)

	bt := ExtractBoundaryTokenFromHTTP([]byte(http))
	if bt == nil {
		t.Fatal("expected Boundary token, got nil")
	}
	if bt.TokenType != BoundaryTokenOpaque {
		t.Errorf("TokenType = %q, want %q", bt.TokenType, BoundaryTokenOpaque)
	}
}

func TestExtractBoundaryTokenNotAJWT(t *testing.T) {
	// JWTs have 2 dots — must NOT be detected as Boundary token
	jwt := buildJWT(`{"sub":"agent","iss":"vault"}`)
	http := fmt.Sprintf("GET /api HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n", jwt)

	bt := ExtractBoundaryTokenFromHTTP([]byte(http))
	if bt != nil {
		t.Errorf("JWT should not be detected as Boundary token, got %+v", bt)
	}
}

func TestExtractBoundaryTokenNoBearer(t *testing.T) {
	http := "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n"
	bt := ExtractBoundaryTokenFromHTTP([]byte(http))
	if bt != nil {
		t.Errorf("expected nil for no-bearer request, got %+v", bt)
	}
}

func TestExtractBoundaryTokenTooShort(t *testing.T) {
	// Short opaque string — not long enough to be a real token
	http := "GET /api HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n"
	bt := ExtractBoundaryTokenFromHTTP([]byte(http))
	if bt != nil {
		t.Errorf("short token should not match, got %+v", bt)
	}
}
