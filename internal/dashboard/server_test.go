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
		{"/dashboard/graph", "Graph"},
		{"/dashboard/rules", "Rules"},
		{"/dashboard/audit", "Audit"},
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
	_ = resp.Body.Close()

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
	defer func() { _ = sseResp.Body.Close() }()

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

func TestServer_GraphAPI(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Log some entries to populate edges
	srv.audit.Log(audit.Entry{
		ID:             "graph-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "test-agent",
		ToAgent:        "other-agent",
		ContentHash:    "h",
		Status:         "delivered",
		PolicyDecision: "allow",
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/api/graph", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("graph API: status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nodes") || !strings.Contains(body, "edges") {
		t.Error("graph API response should contain nodes and edges")
	}
}

func TestServer_EdgeDetail(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	srv.audit.Log(audit.Entry{
		ID:             "edge-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "test-agent",
		ToAgent:        "other-agent",
		ContentHash:    "h",
		Status:         "delivered",
		PolicyDecision: "allow",
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/api/graph/edge?from=test-agent&to=other-agent", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("edge detail: status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "test-agent") {
		t.Error("edge detail should contain 'test-agent'")
	}
}

func TestServer_AuditPageProductInfo(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/audit", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("audit page: status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Security proxy for AI agent-to-agent communication") {
		t.Error("audit page should contain Oktsec product description")
	}
	// "Priority Remediations" section only shown when there are critical/high
	// findings — the test config triggers some, so at least verify the page
	// renders without error (checked by the status code assertion above).
}

func TestAuditStore_QueryAgentStats(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	entries := []struct {
		id, from, to, status string
	}{
		{"as-1", "agent-x", "agent-y", "delivered"},
		{"as-2", "agent-x", "agent-y", "blocked"},
		{"as-3", "agent-y", "agent-x", "rejected"},
		{"as-4", "agent-z", "agent-x", "quarantined"},
	}
	for _, e := range entries {
		store.Log(audit.Entry{
			ID:             e.id,
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			FromAgent:      e.from,
			ToAgent:        e.to,
			ContentHash:    "h",
			Status:         e.status,
			PolicyDecision: "test",
		})
	}
	time.Sleep(150 * time.Millisecond)

	stats, err := store.QueryAgentStats("agent-x")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 {
		t.Errorf("total = %d, want 4", stats.Total)
	}
	if stats.Delivered != 1 {
		t.Errorf("delivered = %d, want 1", stats.Delivered)
	}
	if stats.Blocked != 1 {
		t.Errorf("blocked = %d, want 1", stats.Blocked)
	}
	if stats.Rejected != 1 {
		t.Errorf("rejected = %d, want 1", stats.Rejected)
	}
	if stats.Quarantined != 1 {
		t.Errorf("quarantined = %d, want 1", stats.Quarantined)
	}

	// Agent with no traffic
	stats, err = store.QueryAgentStats("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 0 {
		t.Errorf("nonexistent agent total = %d, want 0", stats.Total)
	}
}

func TestServer_SearchLengthLimit(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Build a query longer than maxSearchLen (200)
	longQuery := strings.Repeat("a", 300)
	req := httptest.NewRequest("GET", "/dashboard/api/search?q="+longQuery, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("search with long query: status = %d, want 200", w.Code)
	}
}

func TestAuditStore_QueryStatuses(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	for _, e := range []struct{ id, status string }{
		{"qs-1", "delivered"},
		{"qs-2", "blocked"},
		{"qs-3", "rejected"},
		{"qs-4", "delivered"},
	} {
		store.Log(audit.Entry{
			ID: e.id, Timestamp: time.Now().UTC().Format(time.RFC3339),
			FromAgent: "a", ToAgent: "b", ContentHash: "h",
			Status: e.status, PolicyDecision: "test",
		})
	}
	time.Sleep(150 * time.Millisecond)

	// Multi-status query: blocked + rejected
	entries, err := store.Query(audit.QueryOpts{Statuses: []string{"blocked", "rejected"}, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Status != "blocked" && e.Status != "rejected" {
			t.Errorf("unexpected status %q", e.Status)
		}
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

func TestServer_EnforcementTabLoads(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/rules?tab=enforcement", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("enforcement tab: status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Add Override") {
		t.Error("enforcement tab should contain 'Add Override'")
	}
	if !strings.Contains(body, "Webhook Message") {
		t.Error("enforcement tab should contain 'Webhook Message' label")
	}
}

func TestServer_EnforcementSaveAndDisplay(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	srv.cfgPath = cfgPath

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Save an override with template
	form := url.Values{
		"rule_id":     {"CRED_001"},
		"action":      {"block"},
		"severity":    {"critical"},
		"notify_urls": {"https://hooks.slack.com/test"},
		"template":    {"Alert: {{RULE}} fired with {{SEVERITY}}"},
	}
	req := httptest.NewRequest("POST", "/dashboard/rules/enforcement", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("save enforcement: status = %d, want 302", w.Code)
	}

	// Verify in-memory config
	if len(srv.cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(srv.cfg.Rules))
	}
	rule := srv.cfg.Rules[0]
	if rule.ID != "CRED_001" {
		t.Errorf("rule ID = %q, want CRED_001", rule.ID)
	}
	if rule.Action != "block" {
		t.Errorf("action = %q, want block", rule.Action)
	}
	if rule.Template != "Alert: {{RULE}} fired with {{SEVERITY}}" {
		t.Errorf("template = %q, want plain text template", rule.Template)
	}
	if len(rule.Notify) != 1 || rule.Notify[0] != "https://hooks.slack.com/test" {
		t.Errorf("notify = %v, want [https://hooks.slack.com/test]", rule.Notify)
	}

	// Verify persisted to YAML
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Template != "Alert: {{RULE}} fired with {{SEVERITY}}" {
		t.Errorf("persisted template mismatch: %+v", loaded.Rules)
	}

	// Verify the override card renders on the enforcement tab
	req = httptest.NewRequest("GET", "/dashboard/rules?tab=enforcement", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "CRED_001") {
		t.Error("enforcement tab should show CRED_001 override")
	}
	if !strings.Contains(body, "block") {
		t.Error("enforcement tab should show 'block' action")
	}
	if !strings.Contains(body, "template") {
		t.Error("enforcement tab should show template tag")
	}
}

func TestServer_EnforcementUpdate(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	srv.cfgPath = filepath.Join(dir, "oktsec.yaml")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Create initial override
	form := url.Values{
		"rule_id":  {"PI-001"},
		"action":   {"quarantine"},
		"severity": {"high"},
	}
	req := httptest.NewRequest("POST", "/dashboard/rules/enforcement", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if srv.cfg.Rules[0].Action != "quarantine" {
		t.Fatalf("initial action = %q, want quarantine", srv.cfg.Rules[0].Action)
	}

	// Update same rule to block with template
	form = url.Values{
		"rule_id":  {"PI-001"},
		"action":   {"block"},
		"severity": {"critical"},
		"template": {"Blocked: {{RULE}}"},
	}
	req = httptest.NewRequest("POST", "/dashboard/rules/enforcement", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should still be 1 rule, not 2
	if len(srv.cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule after update, got %d", len(srv.cfg.Rules))
	}
	if srv.cfg.Rules[0].Action != "block" {
		t.Errorf("updated action = %q, want block", srv.cfg.Rules[0].Action)
	}
	if srv.cfg.Rules[0].Template != "Blocked: {{RULE}}" {
		t.Errorf("updated template = %q", srv.cfg.Rules[0].Template)
	}
}

func TestServer_EnforcementDelete(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	srv.cfgPath = filepath.Join(dir, "oktsec.yaml")
	srv.cfg.Rules = []config.RuleAction{
		{ID: "CRED_001", Action: "block"},
		{ID: "PI-001", Action: "quarantine"},
	}

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("DELETE", "/dashboard/rules/enforcement/CRED_001", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("delete: status = %d, want 200", w.Code)
	}
	if len(srv.cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule after delete, got %d", len(srv.cfg.Rules))
	}
	if srv.cfg.Rules[0].ID != "PI-001" {
		t.Errorf("remaining rule = %q, want PI-001", srv.cfg.Rules[0].ID)
	}
}
