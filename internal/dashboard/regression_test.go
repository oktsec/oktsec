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

// TestRegression_OnsubmitConfirmInterceptor enforces the contract for the
// global submit interceptor. window.confirm is overridden so the custom modal
// can take over; the layout JS must include a submit listener that mirrors the
// click interceptor, drop the onsubmit attribute before re-submitting, and use
// requestSubmit() so the originating button is honored.
func TestRegression_OnsubmitConfirmInterceptor(t *testing.T) {
	body := authedGet(t, "/dashboard").Body.String()
	if !strings.Contains(body, `addEventListener('submit'`) {
		t.Error("layout JS must include a global submit listener for forms using onsubmit confirm")
	}
	if !strings.Contains(body, `removeAttribute('onsubmit')`) {
		t.Error("submit interceptor must drop the onsubmit attribute before re-submitting (otherwise the confirm path recurses)")
	}
	if !strings.Contains(body, `requestSubmit`) {
		t.Error("submit interceptor should prefer form.requestSubmit() so the originating button is honored")
	}
}

// TestRegression_OnsubmitConfirmForms verifies that templates using
// onsubmit="return confirm(...)" remain compatible with the global submit
// interceptor in the layout. If a template switches to a non-confirm onsubmit
// handler, the contract breaks — this guard keeps that visible.
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
		layoutBody := authedGet(t, "/dashboard").Body.String()
		if !strings.Contains(layoutBody, `addEventListener('submit'`) {
			t.Error("template uses onsubmit confirm but layout JS has no submit listener to handle it")
		}
	}
}

// TestRegression_SettingsToggleNoStaleSavedOnRedirect enforces that
// stToggleSave uses redirect:'manual' and explicitly handles opaqueredirect
// so a session-expired POST is surfaced to the user instead of being
// indistinguishable from a successful save.
func TestRegression_SettingsToggleNoStaleSavedOnRedirect(t *testing.T) {
	body := authedGet(t, "/dashboard/settings").Body.String()
	if !strings.Contains(body, `redirect: 'manual'`) && !strings.Contains(body, `redirect:'manual'`) {
		t.Error("stToggleSave must use redirect:'manual' so a session-expired redirect is observable")
	}
	if strings.Contains(body, `r.ok || r.redirected`) {
		t.Error("stToggleSave must distinguish a redirected response from a successful save")
	}
	if !strings.Contains(body, `opaqueredirect`) {
		t.Error("stToggleSave should detect opaqueredirect responses and surface session-expired feedback")
	}
}

// ── Phase 0: Graph rendering invariants (client-agnostic activity layer) ──
//
// These tests lock in the contract for graph rendering:
//   1. The graph code generalizes across MCP clients (no hardcoded display names).
//   2. Edge originators in the graph match the audit trail.
//   3. Tool edges are derived only from observed audit evidence.
//   4. Forward-proxy traffic and edges to non-agent endpoints surface in
//      UnrepresentedRoutes rather than being aggregated out.
//
// These guards stay in place until the activity layer (Phase 1+) ships an
// explicit role/client model that supersedes them.

// TestRegression_GraphCodeIsClientAgnostic fails if a specific client display
// name OR a Claude-shaped event family literal appears in the graph builder,
// the runtime-graph adapter, or the graph template. Replace with a capability
// lookup once the activity layer ships.
//
// Phase 3D adds runtime_graph.go to the watched set and broadens the banned
// substrings beyond "claude-code" to the per-event names ("PreToolUse",
// "SubagentStart", etc.) — those belong in the runtime normalizer, not in
// any code path that builds or renders the graph.
func TestRegression_GraphCodeIsClientAgnostic(t *testing.T) {
	files := []string{
		"handlers.go",
		"tmpl_graph.go",
		"runtime_graph.go",
	}
	bannedLiterals := []string{
		`"claude-code"`,
		`'claude-code'`,
		`"Claude Code"`,
		`"SubagentStart"`,
		`"PreToolUse"`,
		`"PostToolUse"`,
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			// Test runs with CWD = package dir under `go test`, so relative paths
			// resolve to the package source files. Works in CI without hardcoding.
			data, err := readFileForTest(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			lines := strings.Split(data, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				for _, lit := range bannedLiterals {
					if strings.Contains(line, lit) {
						t.Errorf("%s:%d references %s in non-comment code: %s",
							f, i+1, lit, strings.TrimSpace(line))
					}
				}
			}
		})
	}
}

// TestRegression_ToolEdgesAreEvidenceBased exercises buildGraph through the
// public dashboard route with a fixture where one agent calls one tool. The
// graph must emit exactly one tool edge: from the agent that actually called
// the tool. No other agent may appear as caller.
func TestRegression_ToolEdgesAreEvidenceBased(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents = map[string]config.Agent{
		"agent-a": {CanMessage: []string{"agent-b"}},
		"agent-b": {},
	}
	// One tool call from agent-a; nothing from agent-b.
	srv.audit.Log(audit.Entry{
		ID:        "tool-evidence-1",
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
	if strings.Contains(body, `"agent":"agent-b","tool":"read_file"`) {
		t.Error("tool edge for read_file must only appear under agent-a; agent-b never called it")
	}
}

// TestRegression_EdgeOriginatorPreserved feeds the audit a node→node edge and
// verifies the graph renders it with the originator the audit recorded, not a
// substituted node.
func TestRegression_EdgeOriginatorPreserved(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents = map[string]config.Agent{
		"clientX": {CanMessage: []string{"agent-y"}},
		"agent-y": {},
		"gateway": {},
	}
	srv.audit.Log(audit.Entry{
		ID:        "origin-1",
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
		t.Errorf("edge originator must match audit (clientX → agent-y); got %s", body)
	}
}

// TestRegression_UnrepresentedRoutesSurfaced verifies that traffic the graph
// model cannot render as a node-to-node edge (forward-proxy endpoints,
// hostnames, IP:port pairs) is captured in UnrepresentedRoutes so it remains
// visible in the dashboard.
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
		t.Error("graph JSON missing unrepresented_routes — forward-proxy traffic must remain visible")
	}
	if !strings.Contains(body, "api.example.com") {
		t.Error("forward-proxy endpoint api.example.com must appear in unrepresented_routes")
	}
}

// TestRegression_GraphCopyScopedToInstrumentedSurfaces enforces that the graph
// page-desc names the instrumented surfaces (MCP gateway, hooks, stdio
// wrappers) so the page does not generalize beyond what the system observes.
func TestRegression_GraphCopyScopedToInstrumentedSurfaces(t *testing.T) {
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
		t.Errorf("graph page-desc must reference instrumented surfaces (MCP / gateway / hooks); got: %s", desc)
	}
	for _, banned := range []string{
		"Visual map of how your AI agents communicate",
		"all your AI agents",
		"all agents",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("graph page-desc contains overly broad copy %q — must scope to instrumented surfaces", banned)
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

// TestRegression_OverviewRendersCoverageMatrix verifies the Coverage
// section appears in the Overview page with one row per principal and
// the right badges. This is the user-visible payoff of Phase 2A.
func TestRegression_OverviewRendersCoverageMatrix(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals,
		config.PrincipalConfig{
			ID: "local-codex", DisplayName: "local-codex", Kind: "agent",
			Tokens: []config.PrincipalTokenConfig{{
				ID: "tok-1", Type: "gateway_bearer", Hash: "sha256:dummy",
				CreatedAt: "2026-04-26T00:00:00Z",
			}},
		},
		config.PrincipalConfig{
			ID: "researcher", DisplayName: "researcher", Kind: "agent",
			Tokens: []config.PrincipalTokenConfig{{
				ID: "tok-2", Type: "proxy_basic", Hash: "sha256:dummy",
				CreatedAt: "2026-04-26T00:00:00Z",
			}},
		},
	)
	srv.cfg.Gateway.Enabled = true
	srv.cfg.ForwardProxy.Enabled = true
	// Enterprise profile so principals without a token of the matching
	// type fall to blind (not the legacy loopback observed path). That
	// makes the matrix exercise both protected and blind in one go.
	srv.cfg.Deployment.Profile = "enterprise"
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Coverage matrix",      // section header
		"local-codex",          // principal #1
		"researcher",           // principal #2
		"Generic MCP HTTP",     // humanized connector for gateway_bearer-only
		"Generic egress proxy", // humanized connector for proxy_basic-only
		"cov-badge protected",
		"cov-badge blind", // researcher has no gateway_bearer → mcp_http blind in enterprise
		"Bearer token",    // humanized identity for local-codex
		"Proxy token",     // humanized identity for researcher
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Overview missing %q in coverage matrix; first 400 chars after Coverage:\n%s",
				want, snippetAfter(body, "Coverage", 400))
		}
	}
}

func snippetAfter(s, anchor string, n int) string {
	i := strings.Index(s, anchor)
	if i < 0 {
		return "(anchor not found)"
	}
	end := i + n
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

// TestRegression_OverviewCoverageEmptyState verifies the empty state
// when no principals are configured yet — important for first-run
// experience so a fresh install does not look broken.
func TestRegression_OverviewCoverageEmptyState(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.Principals = nil
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "No principals configured yet") {
		t.Errorf("empty state missing; body fragment around Coverage:\n%s",
			snippetAfter(body, "Coverage", 400))
	}
	if !strings.Contains(body, "Issue a bearer token") {
		t.Error("empty state should link to bearer-token guide")
	}
}

// TestRegression_CoverageAPIReturnsJSON exercises the /dashboard/api/coverage
// endpoint added in Phase 2A. It seeds a principal with a gateway_bearer
// token so the matrix has at least one cell with content, then asserts
// the JSON shape contains the surface and the principal id.
func TestRegression_CoverageAPIReturnsJSON(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals, config.PrincipalConfig{
		ID: "local-codex", DisplayName: "local-codex", Kind: "agent",
		Tokens: []config.PrincipalTokenConfig{{
			ID: "tok-1", Type: "gateway_bearer", Hash: "sha256:dummy",
			CreatedAt: "2026-04-26T00:00:00Z",
		}},
	})
	srv.cfg.Gateway.Enabled = true
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"principal_id":"local-codex"`) {
		t.Errorf("response missing principal_id; body=%s", body)
	}
	if !strings.Contains(body, `"surface":"mcp_http"`) {
		t.Errorf("response missing mcp_http surface; body=%s", body)
	}
	if !strings.Contains(body, `"coverage":"protected"`) {
		t.Errorf("gateway_bearer + enabled gateway should produce a protected cell; body=%s", body)
	}
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
