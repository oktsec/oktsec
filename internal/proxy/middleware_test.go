package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSecurityHeaders_SetOnEveryResponse(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/message", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
		"Permissions-Policy":    "interest-cohort=()",
	}
	for key, val := range expected {
		got := rr.Header().Get(key)
		if got != val {
			t.Errorf("%s = %q, want %q", key, got, val)
		}
	}
}

func TestSecurityHeaders_CSPNoExternalDomains(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header not set")
	}

	// Should NOT reference external domains (they were removed in favor of self-hosted assets)
	for _, blocked := range []string{"unpkg.com", "googleapis.com", "gstatic.com"} {
		if strContains(csp, blocked) {
			t.Errorf("CSP references external domain %q: %s", blocked, csp)
		}
	}

	// Should contain self directives
	for _, required := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'"} {
		if !strContains(csp, required) {
			t.Errorf("CSP missing %q: %s", required, csp)
		}
	}
}

func TestSecurityHeaders_DashboardCacheControl(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Dashboard path should get Cache-Control: no-store
	req := httptest.NewRequest("GET", "/dashboard/overview", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("dashboard Cache-Control = %q, want %q", got, "no-store")
	}

	// Non-dashboard path should NOT get Cache-Control
	req2 := httptest.NewRequest("GET", "/v1/message", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if got := rr2.Header().Get("Cache-Control"); got != "" {
		t.Errorf("non-dashboard Cache-Control = %q, want empty", got)
	}
}

func TestRequestID_SetsHeader(t *testing.T) {
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify context has request ID
		id := r.Context().Value(requestIDKey)
		if id == nil {
			t.Error("request_id not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Request-ID"); got == "" {
		t.Error("X-Request-ID header not set")
	}
}

func TestRequestID_Unique(t *testing.T) {
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr1 := httptest.NewRecorder()
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest("GET", "/", nil))
	handler.ServeHTTP(rr2, httptest.NewRequest("GET", "/", nil))

	id1 := rr1.Header().Get("X-Request-ID")
	id2 := rr2.Header().Get("X-Request-ID")
	if id1 == id2 {
		t.Error("request IDs should be unique")
	}
}

func TestRecovery_CatchesPanic(t *testing.T) {
	logger := testLogger()
	handler := recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestRecovery_NoPanic(t *testing.T) {
	logger := testLogger()
	handler := recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestLogging_CapturesStatus(t *testing.T) {
	logger := testLogger()
	handler := logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestStatusWriter_Flush(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, status: 200}
	sw.Flush() // should not panic
}

func TestStatusWriter_Unwrap(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, status: 200}
	if sw.Unwrap() != rr {
		t.Error("Unwrap should return underlying ResponseWriter")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func strContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
