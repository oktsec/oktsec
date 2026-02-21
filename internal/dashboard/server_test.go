package dashboard

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		Agents: map[string]config.Agent{
			"test-agent": {CanMessage: []string{"other-agent"}},
		},
	}

	return NewServer(cfg, store, logger)
}

func TestServer_LoginFlow(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	// 1. GET /dashboard should redirect to login
	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("dashboard without auth: status = %d, want 302", w.Code)
	}

	// 2. GET /dashboard/login should return the login page
	req = httptest.NewRequest("GET", "/dashboard/login", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login page: status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Access") {
		t.Error("login page should contain 'Access'")
	}

	// 3. POST /dashboard/login with wrong code
	form := url.Values{"code": {"00000000"}}
	req = httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("wrong code: status = %d, want 200 (re-render login)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid") {
		t.Error("wrong code response should contain 'Invalid'")
	}

	// 4. POST /dashboard/login with correct code
	form = url.Values{"code": {srv.AccessCode()}}
	req = httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("correct code: status = %d, want 302 redirect", w.Code)
	}

	// Extract session cookie
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie set after login")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}

	// 5. GET /dashboard with session cookie should succeed
	req = httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("dashboard with session: status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Overview") {
		t.Error("dashboard should contain 'Overview'")
	}
}

func TestServer_DashboardPages(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	// Login first
	form := url.Values{"code": {srv.AccessCode()}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	pages := []struct {
		path     string
		contains string
	}{
		{"/dashboard", "Overview"},
		{"/dashboard/logs", "Audit"},
		{"/dashboard/agents", "Agents"},
		{"/dashboard/rules", "Rules"},
	}

	for _, p := range pages {
		req = httptest.NewRequest("GET", p.path, nil)
		req.AddCookie(sessionCookie)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", p.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), p.contains) {
			t.Errorf("%s: body should contain %q", p.path, p.contains)
		}
	}
}
