package auth_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/raygj/workload-ebpf-reflector/internal/auth"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func logger() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

func TestTokenMiddlewareRejectsNoHeader(t *testing.T) {
	t.Setenv("REFLECTOR_API_TOKEN", "secret-token")
	h := auth.TokenMiddleware(okHandler, logger())
	r := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestTokenMiddlewareRejectsWrongToken(t *testing.T) {
	t.Setenv("REFLECTOR_API_TOKEN", "secret-token")
	h := auth.TokenMiddleware(okHandler, logger())
	r := httptest.NewRequest("GET", "/sessions", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestTokenMiddlewareAcceptsCorrectToken(t *testing.T) {
	t.Setenv("REFLECTOR_API_TOKEN", "secret-token")
	h := auth.TokenMiddleware(okHandler, logger())
	r := httptest.NewRequest("GET", "/sessions", nil)
	r.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestTokenMiddlewareUnsetIsNoOp(t *testing.T) {
	_ = os.Unsetenv("REFLECTOR_API_TOKEN")
	h := auth.TokenMiddleware(okHandler, logger())
	r := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 (no-op when token unset), got %d", w.Code)
	}
}

func TestTokenMiddlewareRejectsMalformedScheme(t *testing.T) {
	t.Setenv("REFLECTOR_API_TOKEN", "secret-token")
	h := auth.TokenMiddleware(okHandler, logger())
	for _, hdr := range []string{"secret-token", "Basic secret-token", "bearer secret-token"} {
		r := httptest.NewRequest("GET", "/sessions", nil)
		r.Header.Set("Authorization", hdr)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: want 401, got %d", hdr, w.Code)
		}
	}
}
