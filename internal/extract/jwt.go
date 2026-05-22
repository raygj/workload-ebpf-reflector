package extract

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWTIdentity contains claims extracted from a JWT bearer token.
// We decode the payload without signature verification — the reflector
// is an observer, not a policy enforcement point.
type JWTIdentity struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud,omitempty"`
	// Raw claims map for anything else
	Claims map[string]any
}

// ExtractJWTFromHTTP scans captured HTTP plaintext for an Authorization
// header with a Bearer token, decodes the JWT payload, and returns claims.
// Returns nil if no Bearer token is found.
func ExtractJWTFromHTTP(plaintext []byte) (*JWTIdentity, error) {
	token := findBearerToken(plaintext)
	if token == "" {
		return nil, nil // No bearer token — not an error
	}
	return DecodeJWTPayload(token)
}

// DecodeJWTPayload decodes the payload (middle segment) of a JWT
// without verifying the signature. Returns structured claims.
func DecodeJWTPayload(token string) (*JWTIdentity, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	id := &JWTIdentity{Claims: claims}
	if sub, ok := claims["sub"].(string); ok {
		id.Subject = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		id.Issuer = iss
	}
	if aud, ok := claims["aud"].(string); ok {
		id.Audience = aud
	}
	return id, nil
}

// findBearerToken scans HTTP plaintext for "Authorization: Bearer <token>".
// Handles both \r\n and \n line endings.
func findBearerToken(data []byte) string {
	s := string(data)
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			val := strings.TrimSpace(line[len("authorization:"):])
			if strings.HasPrefix(strings.ToLower(val), "bearer ") {
				return strings.TrimSpace(val[len("bearer "):])
			}
		}
	}
	return ""
}
