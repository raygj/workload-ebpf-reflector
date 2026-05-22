package extract

import (
	"strings"
)

// BoundaryTokenType classifies the detected Boundary token.
type BoundaryTokenType string

const (
	BoundaryTokenAuth    BoundaryTokenType = "auth"    // at_<id> — auth token
	BoundaryTokenSession BoundaryTokenType = "session" // s_<id>  — session token
	BoundaryTokenOpaque  BoundaryTokenType = "opaque"  // opaque UUID-style, no prefix
)

// BoundaryToken is a Boundary session or auth token extracted from HTTP headers.
type BoundaryToken struct {
	Raw       string
	TokenType BoundaryTokenType
}

// ExtractBoundaryTokenFromHTTP scans captured HTTP plaintext for an Authorization
// Bearer token that matches Boundary token format (not a JWT).
//
// Boundary tokens are discriminated from JWTs by structure:
//   - JWTs have exactly two dots (header.payload.signature)
//   - Boundary tokens are opaque — no dots, optional prefix (at_, s_)
//
// Returns nil if no Boundary token is found, or if the bearer token is a JWT.
func ExtractBoundaryTokenFromHTTP(plaintext []byte) *BoundaryToken {
	token := findBearerToken(plaintext)
	if token == "" {
		return nil
	}
	// JWTs have 2 dots — if we see dots, this is a JWT, not a Boundary token.
	if strings.Count(token, ".") >= 2 {
		return nil
	}
	return classifyBoundaryToken(token)
}

// classifyBoundaryToken identifies the token type from its prefix or structure.
func classifyBoundaryToken(token string) *BoundaryToken {
	if token == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(token, "at_"):
		return &BoundaryToken{Raw: token, TokenType: BoundaryTokenAuth}
	case strings.HasPrefix(token, "s_"):
		return &BoundaryToken{Raw: token, TokenType: BoundaryTokenSession}
	default:
		// Opaque UUID-style token: 32+ hex chars, possible hyphens.
		// Must be at least 20 chars to avoid matching short random strings.
		if len(token) >= 20 && isOpaqueToken(token) {
			return &BoundaryToken{Raw: token, TokenType: BoundaryTokenOpaque}
		}
		return nil
	}
}

// isOpaqueToken returns true if the string looks like an opaque token
// (hex chars and hyphens only, no whitespace or special chars that would
// indicate a different token format).
func isOpaqueToken(s string) bool {
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		isSep := c == '-' || c == '_'
		if !isHex && !isSep {
			return false
		}
	}
	return true
}
