package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
	auth := NewAuth()
	if auth.ValidateCode("wrong") {
		t.Error("should reject wrong code")
	}
	if !auth.ValidateCode(auth.AccessCode()) {
		t.Error("should accept correct code")
	}
}

func TestAuth_Session(t *testing.T) {
	auth := NewAuth()
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
	auth := NewAuth()
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
	auth := NewAuth()
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
	auth := NewAuth()
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
	auth := NewAuth()
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
