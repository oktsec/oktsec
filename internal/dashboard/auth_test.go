package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenerateAccessCode(t *testing.T) {
	code := generateAccessCode()
	if len(code) != 8 {
		t.Errorf("code length = %d, want 8", len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("code contains non-digit: %c", c)
		}
	}
}

func TestAuth_ValidateCode(t *testing.T) {
	auth := NewAuth(nil)
	if auth.ValidateCode("wrong") {
		t.Error("should reject wrong code")
	}
	if !auth.ValidateCode(auth.AccessCode()) {
		t.Error("should accept correct code")
	}
}

func TestAuth_Session(t *testing.T) {
	auth := NewAuth(nil)
	token := auth.CreateSession()

	if !auth.ValidateSession(token) {
		t.Error("should validate created session")
	}
	if auth.ValidateSession("bogus-token") {
		t.Error("should reject unknown token")
	}
}

func TestAuth_UniqueAccessCodes(t *testing.T) {
	codes := make(map[string]bool)
	for range 100 {
		code := generateAccessCode()
		codes[code] = true
	}
	// With 8-digit codes and 100 samples, collisions are astronomically unlikely
	if len(codes) < 95 {
		t.Errorf("too many collisions: only %d unique codes from 100", len(codes))
	}
}

func TestAuth_Middleware_RedirectsWithoutSession(t *testing.T) {
	auth := NewAuth(nil)
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard/login" {
		t.Errorf("redirect = %q, want /dashboard/login", loc)
	}
}

func TestAuth_Middleware_AllowsLoginPage(t *testing.T) {
	auth := NewAuth(nil)
	called := false
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("login page handler was not called")
	}
}

func TestAuth_Middleware_AllowsValidSession(t *testing.T) {
	auth := NewAuth(nil)
	token := auth.CreateSession()
	called := false
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler was not called with valid session")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestAuth_Middleware_RejectsInvalidSession(t *testing.T) {
	auth := NewAuth(nil)
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-token"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect", w.Code)
	}
}

func TestAuth_RateLimit_AllowsInitialAttempts(t *testing.T) {
	auth := NewAuth(nil)
	ip := "192.168.1.100"

	// First few attempts should be allowed
	for i := range 4 {
		allowed, _ := auth.CheckRateLimit(ip)
		if !allowed {
			t.Fatalf("attempt %d should be allowed", i)
		}
		auth.RecordFailure(ip)
	}
}

func TestAuth_RateLimit_LocksAfterThreshold(t *testing.T) {
	auth := NewAuth(nil)
	ip := "192.168.1.101"

	// Trigger lockout (5 failures)
	for range lockoutThreshold {
		auth.RecordFailure(ip)
	}

	allowed, retryAfter := auth.CheckRateLimit(ip)
	if allowed {
		t.Error("should be locked out after threshold failures")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive during lockout")
	}
}

func TestAuth_RateLimit_ClearsOnSuccess(t *testing.T) {
	auth := NewAuth(nil)
	ip := "192.168.1.102"

	// Record some failures (but below lockout)
	for range 3 {
		auth.RecordFailure(ip)
	}

	// Successful login clears record
	auth.RecordSuccess(ip)

	// Should be fully allowed again
	allowed, _ := auth.CheckRateLimit(ip)
	if !allowed {
		t.Error("should be allowed after successful login")
	}
}

func TestAuth_RateLimit_EscalatingLockout(t *testing.T) {
	auth := NewAuth(nil)
	ip := "192.168.1.103"

	// Tier 0: 5 failures → 5 min lockout
	for range lockoutThreshold {
		auth.RecordFailure(ip)
	}
	_, retry0 := auth.CheckRateLimit(ip)

	// Simulate lockout expiry: reset counter but keep tier
	auth.mu.Lock()
	att := auth.attempts[ip]
	att.lockedUntil = time.Now().Add(-1 * time.Second) // expired
	att.failures = 0
	auth.mu.Unlock()

	// Tier 1: 5 more failures → 30 min lockout
	for range lockoutThreshold {
		auth.RecordFailure(ip)
	}
	_, retry1 := auth.CheckRateLimit(ip)

	if retry1 <= retry0 {
		t.Errorf("lockout should escalate: tier0=%v, tier1=%v", retry0, retry1)
	}
}

func TestAuth_RateLimit_ResetsAfterLockoutExpires(t *testing.T) {
	auth := NewAuth(nil)
	ip := "192.168.1.104"

	// Trigger lockout
	for range lockoutThreshold {
		auth.RecordFailure(ip)
	}

	allowed, _ := auth.CheckRateLimit(ip)
	if allowed {
		t.Fatal("should be locked out")
	}

	// Simulate lockout expiry
	auth.mu.Lock()
	auth.attempts[ip].lockedUntil = time.Now().Add(-1 * time.Second)
	auth.mu.Unlock()

	// Should be allowed again with fresh attempts
	allowed, _ = auth.CheckRateLimit(ip)
	if !allowed {
		t.Error("should be allowed after lockout expires")
	}

	// Should be able to fail a few times before re-locking
	for range lockoutThreshold - 1 {
		lockout := auth.RecordFailure(ip)
		if lockout > 0 {
			t.Fatal("should not lock out before reaching threshold again")
		}
	}
}

func TestAuth_InvalidateSession(t *testing.T) {
	auth := NewAuth(nil)
	token := auth.CreateSession()

	if !auth.ValidateSession(token) {
		t.Fatal("session should be valid before invalidation")
	}

	auth.InvalidateSession(token)

	if auth.ValidateSession(token) {
		t.Error("session should be invalid after logout")
	}
}

func TestAuth_ConstantTimeValidation(t *testing.T) {
	auth := NewAuth(nil)
	// Verify correct code still works with constant-time compare
	if !auth.ValidateCode(auth.AccessCode()) {
		t.Error("should accept correct code with constant-time compare")
	}
	if auth.ValidateCode("00000000") && auth.AccessCode() != "00000000" {
		t.Error("should reject wrong code")
	}
}

func TestAuth_Cleanup(t *testing.T) {
	auth := NewAuth(nil)

	// Create a session and record a failure
	auth.CreateSession()
	auth.RecordFailure("10.0.0.1")

	// Cleanup should not panic or error
	auth.Cleanup()

	// Session should still be valid (not expired)
	if auth.SessionCount() == 0 {
		t.Error("active sessions should not be cleaned up")
	}
}
