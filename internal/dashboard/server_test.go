package dashboard

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
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

	scanner := engine.NewScanner("")
	t.Cleanup(scanner.Close)

	return NewServer(cfg, "", store, identity.NewKeyStore(), scanner, logger)
}

func loginSession(t *testing.T, srv *Server, handler http.Handler) *http.Cookie {
	t.Helper()

	form := url.Values{"code": {srv.AccessCode()}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("no session cookie after login")
	return nil
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
	cookie := loginSession(t, srv, handler)

	pages := []struct {
		path     string
		contains string
	}{
		{"/dashboard", "Overview"},
		{"/dashboard/events", "Events"},
		{"/dashboard/agents", "Agents"},
		{"/dashboard/rules", "Rules"},
		{"/dashboard/settings", "Settings"},
	}

	for _, p := range pages {
		req := httptest.NewRequest("GET", p.path, nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", p.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), p.contains) {
			t.Errorf("%s: body should contain %q", p.path, p.contains)
		}
	}
}

func TestServer_SSEEndpoint(t *testing.T) {
	srv := newTestServer(t)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Login: POST without following redirect to capture the Set-Cookie header
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	form := url.Values{"code": {srv.AccessCode()}}
	resp, err := client.PostForm(ts.URL+"/dashboard/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Extract session cookie from the 302 response
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie from login")
	}

	// SSE request with session cookie
	sseClient := ts.Client()
	sseClient.Timeout = 500 * time.Millisecond
	req, _ := http.NewRequest("GET", ts.URL+"/dashboard/api/events", nil)
	req.AddCookie(sessionCookie)

	sseResp, err := sseClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sseResp.Body.Close()

	if ct := sseResp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("SSE content-type = %q, want text/event-stream", ct)
	}
}

func TestServer_SearchEndpoint(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Log a test entry
	srv.audit.Log(audit.Entry{
		ID:             "test-search-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "search-agent",
		ToAgent:        "target-agent",
		ContentHash:    "abc123",
		Status:         "delivered",
		PolicyDecision: "allowed",
	})
	time.Sleep(100 * time.Millisecond) // wait for async write

	req := httptest.NewRequest("GET", "/dashboard/api/search?q=search-agent", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("search: status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "search-agent") {
		t.Error("search results should contain 'search-agent'")
	}
}

func TestServer_EventDetail(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Log a test entry
	srv.audit.Log(audit.Entry{
		ID:             "detail-test-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "agent-a",
		ToAgent:        "agent-b",
		ContentHash:    "hash123",
		Status:         "blocked",
		RulesTriggered: "PROMPT-001,EXFIL-002",
		PolicyDecision: "blocked by rule",
		LatencyMs:      42,
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/api/event/detail-test-1", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("event detail: status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "agent-a") {
		t.Error("event detail should contain 'agent-a'")
	}
	if !strings.Contains(body, "PROMPT-001") {
		t.Error("event detail should contain 'PROMPT-001'")
	}
}

func TestServer_EventDetailNotFound(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/event/nonexistent", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("event detail not found: status = %d, want 404", w.Code)
	}
}

func TestAuditStore_QueryByID(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	store.Log(audit.Entry{
		ID:             "qbi-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "a",
		ToAgent:        "b",
		ContentHash:    "h",
		Status:         "delivered",
		PolicyDecision: "allowed",
	})
	time.Sleep(100 * time.Millisecond)

	entry, err := store.QueryByID("qbi-1")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.FromAgent != "a" {
		t.Errorf("from_agent = %q, want 'a'", entry.FromAgent)
	}

	// Not found
	entry, err = store.QueryByID("nope")
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Error("expected nil for nonexistent ID")
	}
}

func TestAuditStore_QueryStats(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	for i, status := range []string{"delivered", "delivered", "blocked", "rejected"} {
		store.Log(audit.Entry{
			ID:             fmt.Sprintf("stat-%d", i),
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			FromAgent:      "a",
			ToAgent:        "b",
			ContentHash:    "h",
			Status:         status,
			PolicyDecision: "test",
		})
	}
	time.Sleep(150 * time.Millisecond)

	stats, err := store.QueryStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 {
		t.Errorf("total = %d, want 4", stats.Total)
	}
	if stats.Delivered != 2 {
		t.Errorf("delivered = %d, want 2", stats.Delivered)
	}
	if stats.Blocked != 1 {
		t.Errorf("blocked = %d, want 1", stats.Blocked)
	}
}

func TestAuditStore_Search(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	store.Log(audit.Entry{
		ID: "s1", Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "alpha", ToAgent: "beta", ContentHash: "h",
		Status: "delivered", PolicyDecision: "allowed",
	})
	store.Log(audit.Entry{
		ID: "s2", Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "gamma", ToAgent: "delta", ContentHash: "h",
		Status: "blocked", PolicyDecision: "blocked",
	})
	time.Sleep(150 * time.Millisecond)

	entries, err := store.Query(audit.QueryOpts{Search: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("search 'alpha': got %d, want 1", len(entries))
	}
	if entries[0].FromAgent != "alpha" {
		t.Errorf("from_agent = %q, want 'alpha'", entries[0].FromAgent)
	}
}

func TestServer_QuarantinePageLoads(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/events?tab=quarantine", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("quarantine page: status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Quarantine") {
		t.Error("quarantine page should contain 'Quarantine'")
	}
}

func TestServer_QuarantineApproveReject(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Insert audit entry and quarantine item
	srv.audit.Log(audit.Entry{
		ID:             "q-test-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "a",
		ToAgent:        "b",
		ContentHash:    "h",
		Status:         "quarantined",
		PolicyDecision: "content_quarantined",
	})
	time.Sleep(100 * time.Millisecond)

	_ = srv.audit.Enqueue(audit.QuarantineItem{
		ID:           "q-test-1",
		AuditEntryID: "q-test-1",
		Content:      "test content",
		FromAgent:    "a",
		ToAgent:      "b",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	})

	// Approve
	req := httptest.NewRequest("POST", "/dashboard/api/quarantine/q-test-1/approve", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("approve: status = %d, want 200", w.Code)
	}

	item, _ := srv.audit.QuarantineByID("q-test-1")
	if item.Status != "approved" {
		t.Errorf("status = %q, want approved", item.Status)
	}
}

func TestServer_LegacyRedirects(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	redirects := []struct {
		from string
		to   string
	}{
		{"/dashboard/logs", "/dashboard/events"},
		{"/dashboard/quarantine", "/dashboard/events?tab=quarantine"},
		{"/dashboard/analytics", "/dashboard"},
		{"/dashboard/identity", "/dashboard/settings"},
	}

	for _, r := range redirects {
		req := httptest.NewRequest("GET", r.from, nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMovedPermanently {
			t.Errorf("%s: status = %d, want 301", r.from, w.Code)
		}
		loc := w.Header().Get("Location")
		if loc != r.to {
			t.Errorf("%s: redirect to %q, want %q", r.from, loc, r.to)
		}
	}
}

func TestServer_AgentCreate(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	form := url.Values{
		"name":        {"new-agent"},
		"description": {"Test agent"},
		"can_message": {"target-agent"},
		"location":    {"test-runner"},
		"tags":        {"test, dev"},
	}
	req := httptest.NewRequest("POST", "/dashboard/agents", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("create agent: status = %d, want 302", w.Code)
	}

	agent, ok := srv.cfg.Agents["new-agent"]
	if !ok {
		t.Fatal("agent should exist in config")
	}
	if agent.Description != "Test agent" {
		t.Errorf("description = %q, want 'Test agent'", agent.Description)
	}
	if agent.Location != "test-runner" {
		t.Errorf("location = %q, want 'test-runner'", agent.Location)
	}
}

func TestServer_AgentDelete(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Verify test-agent exists
	if _, ok := srv.cfg.Agents["test-agent"]; !ok {
		t.Fatal("test-agent should exist before delete")
	}

	req := httptest.NewRequest("DELETE", "/dashboard/agents/test-agent", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("delete agent: status = %d, want 200", w.Code)
	}

	if _, ok := srv.cfg.Agents["test-agent"]; ok {
		t.Error("test-agent should be deleted from config")
	}
}

func TestAuditStore_Hub(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ch := store.Hub.Subscribe()
	defer store.Hub.Unsubscribe(ch)

	store.Log(audit.Entry{
		ID: "hub-1", Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "x", ToAgent: "y", ContentHash: "h",
		Status: "delivered", PolicyDecision: "ok",
	})

	select {
	case entry := <-ch:
		if entry.ID != "hub-1" {
			t.Errorf("broadcast entry ID = %q, want 'hub-1'", entry.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for broadcast")
	}
}
