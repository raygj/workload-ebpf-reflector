package extract

import (
	"encoding/base64"
	"fmt"
	"testing"
)

// buildJWT constructs a minimal JWT with the given payload JSON.
func buildJWT(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

func TestExtractJWTFromHTTP(t *testing.T) {
	token := buildJWT(`{"sub":"spiffe://prod/agent/deploy","iss":"vault","aud":"api"}`)
	http := fmt.Sprintf("POST /v1/secrets HTTP/1.1\r\nHost: vault.prod:8200\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n\r\n{}", token)

	id, err := ExtractJWTFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("ExtractJWTFromHTTP: %v", err)
	}
	if id == nil {
		t.Fatal("expected JWT identity, got nil")
	}
	if id.Subject != "spiffe://prod/agent/deploy" {
		t.Errorf("Subject = %q, want %q", id.Subject, "spiffe://prod/agent/deploy")
	}
	if id.Issuer != "vault" {
		t.Errorf("Issuer = %q, want %q", id.Issuer, "vault")
	}
	if id.Audience != "api" {
		t.Errorf("Audience = %q, want %q", id.Audience, "api")
	}
}

func TestExtractJWTFromHTTPNoBearer(t *testing.T) {
	http := "GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	id, err := ExtractJWTFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil for no-bearer request, got %+v", id)
	}
}

func TestExtractJWTFromHTTPCaseInsensitive(t *testing.T) {
	token := buildJWT(`{"sub":"agent-42"}`)
	http := fmt.Sprintf("GET /api HTTP/1.1\r\nauthorization: bearer %s\r\n\r\n", token)

	id, err := ExtractJWTFromHTTP([]byte(http))
	if err != nil {
		t.Fatalf("ExtractJWTFromHTTP: %v", err)
	}
	if id == nil {
		t.Fatal("expected JWT identity, got nil")
	}
	if id.Subject != "agent-42" {
		t.Errorf("Subject = %q, want %q", id.Subject, "agent-42")
	}
}

func TestDecodeJWTPayload(t *testing.T) {
	token := buildJWT(`{"sub":"test-subject","iss":"test-issuer","custom_claim":"hello"}`)
	id, err := DecodeJWTPayload(token)
	if err != nil {
		t.Fatalf("DecodeJWTPayload: %v", err)
	}
	if id.Subject != "test-subject" {
		t.Errorf("Subject = %q, want %q", id.Subject, "test-subject")
	}
	if id.Claims["custom_claim"] != "hello" {
		t.Errorf("custom_claim = %v, want %q", id.Claims["custom_claim"], "hello")
	}
}

func TestDecodeJWTPayloadInvalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no dots", "nodots"},
		{"one dot", "one.dot"},
		{"bad base64", "header.!!!invalid!!!.sig"},
		{"bad json", fmt.Sprintf("h.%s.s", base64.RawURLEncoding.EncodeToString([]byte("not json")))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeJWTPayload(tt.token)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
