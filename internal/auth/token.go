// Package auth provides HTTP and gRPC authentication middleware.
package auth

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
)

const tokenEnvVar = "REFLECTOR_API_TOKEN"

// TokenMiddleware returns an HTTP middleware that enforces bearer token auth.
// If REFLECTOR_API_TOKEN is unset, the middleware is a no-op and a warning is
// logged once at construction time (warn-and-run; ADR-013).
func TokenMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	token := os.Getenv(tokenEnvVar)
	if token == "" {
		logger.Warn("REFLECTOR_API_TOKEN unset — HTTP API is unauthenticated (set token for pilot/prod)")
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") || strings.TrimPrefix(hdr, "Bearer ") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
