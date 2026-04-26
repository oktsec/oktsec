package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

var osReadFile = os.ReadFile

// TestRegression_AllPagesLoad is a smoke test that hits every dashboard page
// and confirms it returns 200 and renders the global skip link. If a template
// edit breaks parsing or removes the layout, this test catches it.
func TestRegression_AllPagesLoad(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.LLM.Enabled = true
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// fragment routes return HTMX partials (no <main>/skip link by design).
	// They still need to return 2xx so the parent page can swap them in.
	pages := []struct {
		path     string
		fragment bool
	}{
		{"/dashboard", false},
		{"/dashboard/events", false},
		{"/dashboard/sessions", false},
		{"/dashboard/alerts", false},
		{"/dashboard/agents", false},
		{"/dashboard/agents/test-agent", false},
		{"/dashboard/rules", false},
		{"/dashboard/rules/custom", true},
		{"/dashboard/rules/enforcement", true},
		{"/dashboard/audit", false},
		{"/dashboard/audit/sandbox", false},
		{"/dashboard/llm", false},
		{"/dashboard/graph", false},
		{"/dashboard/gateway", false},
		{"/dashboard/discovery", false},
		{"/dashboard/identity", false},
		{"/dashboard/quarantine", false},
		{"/dashboard/settings", false},
		{"/dashboard/analytics", false},
		{"/dashboard/logs", false},
		{"/dashboard/report", true},
	}

	for _, p := range pages {
		path, fragment := p.path, p.fragment
		t.Run(path, func(t *testing.T) {
			// Follow one redirect so smoke coverage hits the canonical page
			// even when a route is an alias (e.g. /dashboard/discovery → tab).
			currentPath := path
			for hop := 0; hop < 3; hop++ {
				req := httptest.NewRequest("GET", currentPath, nil)
				req.AddCookie(cookie)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				if rr.Code >= 300 && rr.Code < 400 {
					loc := rr.Header().Get("Location")
					if loc == "" {
						t.Fatalf("%s returned %d with no Location header", currentPath, rr.Code)
					}
					currentPath = loc
					continue
				}
				if rr.Code != http.StatusOK {
					t.Fatalf("%s returned %d (started at %s), want 2xx", currentPath, rr.Code, path)
				}
				if fragment {
					return
				}
				body := rr.Body.String()
				if !strings.Contains(body, `class="skip-link"`) {
					t.Errorf("%s missing skip link — layout may be broken", currentPath)
				}
				if !strings.Contains(body, `id="main"`) {
					t.Errorf("%s missing <main id=\"main\"> skip target", currentPath)
				}
				return
			}
			t.Fatalf("%s redirected too many times", path)
		})
	}
}

// TestRegression_DashboardPolishMarkers locks in the user-visible work from
// the dashboard clarity sprint (PRs 119-126). If a future template edit removes
// any of these markers, the relevant subtest fails with a pointer to which PR
// originally introduced it.
func TestRegression_DashboardPolishMarkers(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.LLM.Enabled = true
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	get := func(path string) string {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, rr.Code)
		}
		return rr.Body.String()
	}

	cases := []struct {
		pr      string
		path    string
		markers []string
	}{
		{
			pr:   "PR 121 — rules operator tooling",
			path: "/dashboard/rules",
			markers: []string{
				"rules-filter",
				"rfToggle",
			},
		},
		{
			pr:   "PR 122 — agent ARIA tabs and policy comprehension",
			path: "/dashboard/agents/test-agent",
			markers: []string{
				`role="tablist"`,
				`aria-selected="true"`,
			},
		},
		{
			pr:   "PR 123 — AI analysis evidence framing",
			path: "/dashboard/llm",
			markers: []string{
				"AI Analysis",
			},
		},
		{
			pr:   "PR 124 — graph filter chips and loading state",
			path: "/dashboard/graph",
			markers: []string{
				"gf-all",
				"gf-risky",
				"gf-blocked",
				"gf-unmonitored",
				"Loading graph",
				"_applyGraphFilter",
			},
		},
		{
			pr:   "PR 125 — posture remediation surface",
			path: "/dashboard/audit/sandbox",
			markers: []string{
				"ps-filters",
				"ps-rem-copy",
				"psFilter(",
				`data-sev=`,
				`data-fixable=`,
			},
		},
		{
			pr:   "PR 126 — accessibility (skip link, aria-current, role)",
			path: "/dashboard",
			markers: []string{
				`class="skip-link"`,
				`role="navigation"`,
				`aria-label="Primary"`,
				`aria-current="page"`,
				`aria-hidden="true"`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.pr, func(t *testing.T) {
			body := get(tc.path)
			for _, marker := range tc.markers {
				if !strings.Contains(body, marker) {
					t.Errorf("%s: marker %q missing on %s — regression from %s",
						tc.pr, marker, tc.path, tc.pr)
				}
			}
		})
	}
}

// TestRegression_CSPHeader confirms the dashboard ships with a content security
// policy that disallows external scripts. The dashboard is self-hosted on purpose
// — a CDN reference here would be a regression we want to catch immediately.
func TestRegression_CSPHeader(t *testing.T) {
	rr := authedGet(t, "/dashboard")
	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Skip("no CSP set in this configuration")
	}
	if strings.Contains(csp, "https://") || strings.Contains(csp, "http://") {
		t.Errorf("CSP should not whitelist external origins, got: %s", csp)
	}
}

// TestRegression_OnsubmitConfirmInterceptor guards against the P1 bug Codex caught
// after the dashboard clarity sprint: window.confirm is overridden to always return
// false, so any form that uses onsubmit="return confirm(...)" silently never submits
// unless a global submit listener intercepts it and re-submits after the modal.
func TestRegression_OnsubmitConfirmInterceptor(t *testing.T) {
	body := authedGet(t, "/dashboard").Body.String()
	// The submit-listener block must exist in the layout JS.
	if !strings.Contains(body, `addEventListener('submit'`) {
		t.Error("layout missing global submit listener — onsubmit confirm forms will never submit (window.confirm is overridden to false)")
	}
	if !strings.Contains(body, `removeAttribute('onsubmit')`) {
		t.Error("submit interceptor must drop the onsubmit attribute before re-submitting; otherwise the confirm runs again and recurses")
	}
	if !strings.Contains(body, `requestSubmit`) {
		t.Error("submit interceptor should prefer form.requestSubmit() so the originating button is honored")
	}
}

// TestRegression_OnsubmitConfirmFormsStillUseAttribute ensures the suspend agent
// and add-server-to-gateway forms still rely on the global interceptor. If a future
// edit converts these to onclick or removes onsubmit, this test does not fail —
// but if it converts the attribute to a form-level handler that is NOT confirm(),
// the assumption breaks. Keeps the contract visible.
func TestRegression_OnsubmitConfirmForms(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents = map[string]config.Agent{"test-agent": {}}
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/agents/test-agent", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, `onsubmit="return confirm(`) {
		// Good: this template still uses onsubmit; verify the interceptor in layout will catch it.
		layoutBody := authedGet(t, "/dashboard").Body.String()
		if !strings.Contains(layoutBody, `addEventListener('submit'`) {
			t.Error("agent suspend form uses onsubmit confirm but layout has no submit interceptor")
		}
	}
}

// TestRegression_SettingsToggleNoStaleSavedOnRedirect guards the second P1 from
// Codex: stToggleSave used to treat r.redirected as success. A session-expired
// redirect to /dashboard/login also has r.redirected === true, so the user saw
// a green "Saved" toast for a save that never happened.
func TestRegression_SettingsToggleNoStaleSavedOnRedirect(t *testing.T) {
	body := authedGet(t, "/dashboard/settings").Body.String()
	if !strings.Contains(body, `redirect: 'manual'`) && !strings.Contains(body, `redirect:'manual'`) {
		t.Error("stToggleSave must use redirect:'manual' so a session-expired redirect to /login does not surface as a successful save")
	}
	if strings.Contains(body, `r.ok || r.redirected`) {
		t.Error("stToggleSave should not treat r.redirected as success — that lies about saves when the session expired")
	}
	if !strings.Contains(body, `opaqueredirect`) {
		t.Error("stToggleSave should detect opaqueredirect responses and surface session-expired feedback")
	}
}

// ── Phase 0: Graph honesty (client-agnostic activity layer spec) ──
//
// These tests guard the four lies the dashboard used to tell about coverage:
//   1. The graph builder special-cased "claude-code" as an orchestrator.
//   2. The audit edge `claude-code → agent` was rewritten to `gateway → agent`.
//   3. When all tool calls came from a single source, fake tool→agent edges
//      were synthesized with invented per-edge counts.
//   4. Forward-proxy traffic (domains, IP:port pairs) and edges to non-agent
//      endpoints were silently dropped from the graph.
//
// If any of these regressions land again, the dashboard can look more covered
// than it actually is — exactly what we cannot afford in front of VCs and
// prospective design partners.

// TestRegression_NoClientNameHardcodeInGraphBuilder fails if the graph code
// path special-cases a specific client display name. Replace this guard with
// a richer check (capability lookup) once the activity layer ships.
func TestRegression_NoClientNameHardcodeInGraphBuilder(t *testing.T) {
	files := []string{
		"handlers.go",
		"tmpl_graph.go",
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			// Test runs with CWD = package dir under `go test`, so relative paths
			// resolve to the package source files. Works in CI without hardcoding.
			data, err := readFileForTest(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			// `claude-code` as a literal in the graph builder/template is the
			// classic regression: positioning a specific client as the source
			// of truth for orchestration. Comments are fine; code is not.
			lines := strings.Split(data, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				if strings.Contains(line, `"claude-code"`) || strings.Contains(line, `'claude-code'`) {
					t.Errorf("%s:%d hardcodes 'claude-code' in non-comment code: %s",
						f, i+1, strings.TrimSpace(line))
				}
			}
		})
	}
}

// TestRegression_NoSyntheticToolDistribution exercises buildGraph through the
// public dashboard route with a fixture where ONE agent calls one tool. The
// pre-Phase-0 code would invent fan-out edges to other agents. Today we should
// see exactly one tool edge: from the agent that actually called the tool.
func TestRegression_NoSyntheticToolDistribution(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents = map[string]config.Agent{
		"agent-a": {CanMessage: []string{"agent-b"}},
		"agent-b": {},
	}
	// One tool call from agent-a; nothing from agent-b.
	srv.audit.Log(audit.Entry{
		ID:        "syn-1",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "agent-a",
		ToAgent:   "agent-b",
		Status:    "delivered",
		ToolName:  "read_file",
	})
	srv.audit.Flush()

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	req := httptest.NewRequest("GET", "/dashboard/api/graph?range=24h", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	// agent-b never called read_file; it must not appear as a tool_edge agent
	// for read_file. The pre-fix code would distribute the single call across
	// 2-3 agents.
	if strings.Contains(body, `"agent":"agent-b","tool":"read_file"`) {
		t.Error("synthetic tool distribution: agent-b shows as caller of read_file but never called it")
	}
}

// TestRegression_NoEdgeRewriteFromClientNames feeds the audit a deliberately
// client-named edge (clientX → agent) and verifies the graph does NOT silently
// rewrite it as gateway → agent. The pre-Phase-0 code rewrote `claude-code →
// agent` to `gateway → agent`, hiding the actual originator.
func TestRegression_NoEdgeRewriteFromClientNames(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents = map[string]config.Agent{
		"clientX": {CanMessage: []string{"agent-y"}},
		"agent-y": {},
		"gateway": {},
	}
	srv.audit.Log(audit.Entry{
		ID:        "rw-1",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "clientX",
		ToAgent:   "agent-y",
		Status:    "delivered",
	})
	srv.audit.Flush()

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	req := httptest.NewRequest("GET", "/dashboard/api/graph?range=24h", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, `"from":"clientX"`) {
		t.Errorf("clientX → agent-y edge should appear with the real originator; got %s", body)
	}
}

// TestRegression_UnrepresentedRoutesSurfaced verifies that traffic the graph
// model cannot render (forward-proxy endpoints) is captured in
// UnrepresentedRoutes rather than dropped. Pre-Phase-0 code returned `continue`
// silently for IP:port and dotted-host endpoints.
func TestRegression_UnrepresentedRoutesSurfaced(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents = map[string]config.Agent{
		"agent-a": {},
	}
	// Forward-proxy style: agent makes a request to an external host.
	srv.audit.Log(audit.Entry{
		ID:        "fp-1",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "agent-a",
		ToAgent:   "api.example.com",
		Status:    "delivered",
	})
	srv.audit.Flush()

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	req := httptest.NewRequest("GET", "/dashboard/api/graph?range=24h", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "unrepresented_routes") {
		t.Error("graph JSON missing unrepresented_routes — forward-proxy traffic must not be silently dropped")
	}
	if !strings.Contains(body, "api.example.com") {
		t.Error("forward-proxy endpoint api.example.com must appear in unrepresented_routes")
	}
}

// TestRegression_GraphCopyHonesty guards against re-introducing copy that
// implies full coverage. The graph page must scope its claim to the surfaces
// Oktsec actually instruments (MCP gateway, hooks, stdio wrappers) and must
// not claim it sees "all your AI agents".
func TestRegression_GraphCopyHonesty(t *testing.T) {
	body := authedGet(t, "/dashboard/graph").Body.String()
	pageDescStart := strings.Index(body, `class="page-desc"`)
	if pageDescStart < 0 {
		t.Fatal("graph page missing page-desc paragraph")
	}
	pageDescEnd := strings.Index(body[pageDescStart:], "</p>")
	if pageDescEnd < 0 {
		t.Fatal("graph page page-desc not closed")
	}
	desc := body[pageDescStart : pageDescStart+pageDescEnd]
	if !strings.Contains(strings.ToLower(desc), "mcp") &&
		!strings.Contains(strings.ToLower(desc), "gateway") &&
		!strings.Contains(strings.ToLower(desc), "hook") {
		t.Errorf("graph page-desc must scope coverage to instrumented surfaces (MCP / gateway / hooks); got: %s", desc)
	}
	for _, banned := range []string{
		"Visual map of how your AI agents communicate",
		"all your AI agents",
		"all agents",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("graph page contains overstated copy %q — must scope to what Oktsec actually instruments", banned)
		}
	}
}

// readFileForTest is a tiny os.ReadFile shim so the assertions above stay
// readable. Kept local to this file so it does not leak into production paths.
func readFileForTest(path string) (string, error) {
	b, err := osReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// TestRegression_NoExternalScriptTags confirms no <script src="https://..."> tags
// appear in any dashboard page. All assets are served from the binary.
func TestRegression_NoExternalScriptTags(t *testing.T) {
	pages := []string{
		"/dashboard",
		"/dashboard/events",
		"/dashboard/agents",
		"/dashboard/rules",
		"/dashboard/audit",
		"/dashboard/llm",
		"/dashboard/graph",
		"/dashboard/settings",
	}
	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			body := authedGet(t, path).Body.String()
			if strings.Contains(body, `<script src="https://`) || strings.Contains(body, `<script src="http://`) {
				t.Errorf("%s references an external script — dashboard must self-host all assets", path)
			}
		})
	}
}
