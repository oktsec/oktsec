package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// allDashboardPageRoutes is the page-route inventory the desktop
// acceptance smoke walks. Routes that take a path parameter (event
// detail, agent detail, rule detail, session trace, MCP server
// detail) are exercised by their own focused tests once the
// prerequisites are seeded; this list is the "every top-level
// surface renders" gate.
//
// Kept separate from topbar_mode_test.go's identical list on
// purpose — the topbar test asserts on the mode pill, this one
// asserts on the basic render contract. A single source-of-truth
// list would couple the two regressions; keeping them parallel
// means a route added to one place still gets the other test
// loudly when CI catches the divergence.
var allDashboardPageRoutes = []string{
	"/dashboard",
	"/dashboard/events",
	"/dashboard/sessions",
	"/dashboard/alerts",
	"/dashboard/agents",
	"/dashboard/rules",
	"/dashboard/audit",
	"/dashboard/llm",
	"/dashboard/graph",
	"/dashboard/gateway",
	"/dashboard/settings",
}

// TestAllPagesRender_HappyPath is the consolidated desktop
// acceptance gate: every top-level dashboard page must return 200
// with an authenticated session, ship a strict CSP that does not
// contain unsafe-eval, and not surface obvious failure markers
// (panic stack traces, generic "Internal Server Error", or 404
// titles for routes that should exist).
//
// Individual contract tests (topbar mode, public-artifact sweep,
// drawer wording, typography) cover the deeper invariants per page.
// This test is the single fast check that everything still loads
// before anyone records a walkthrough.
func TestAllPagesRender_HappyPath(t *testing.T) {
	srv := newTestServer(t)
	// Seed enough state so pages don't render the empty state and
	// hide whole UI sections from the smoke. One agent + an
	// enabled gateway is the minimum that exercises the populated
	// rendering paths across every surface.
	srv.cfg.Agents["smoke-agent"] = config.Agent{}
	srv.cfg.Gateway.Enabled = true

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	for _, path := range allDashboardPageRoutes {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body snippet = %s",
					rr.Code, snippetForSmoke(rr.Body.String(), 200))
			}

			// Strict CSP must hold across every page so the cell
			// drill-down (and any future HTMX wiring) keeps working.
			csp := rr.Header().Get("Content-Security-Policy")
			if strings.Contains(csp, "unsafe-eval") {
				t.Errorf("page %s relaxes CSP with unsafe-eval; got %q", path, csp)
			}

			// Failure markers we should never ship into a render path.
			body := rr.Body.String()
			for _, marker := range []string{
				"runtime error: ",
				"goroutine ",
				"Internal Server Error",
				"<title>404",
			} {
				if strings.Contains(body, marker) {
					t.Errorf("page %s contains failure marker %q", path, marker)
				}
			}
		})
	}
}

// TestAllPagesRender_RequireSignatureFlipsOK is the same smoke
// against require_signature: true (the production-leaning config).
// A handler that breaks under enforce-mode rendering would be
// invisible to TestAllPagesRender_HappyPath alone; running the
// inventory under both modes is cheap and catches a class of
// "I added a code path that only runs in enforce" regressions.
func TestAllPagesRender_RequireSignatureFlipsOK(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.RequireSignature = true
	srv.cfg.Agents["smoke-agent"] = config.Agent{}
	srv.cfg.Gateway.Enabled = true

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	for _, path := range allDashboardPageRoutes {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (require_signature=true); body snippet = %s",
					rr.Code, snippetForSmoke(rr.Body.String(), 200))
			}
		})
	}
}

// snippetForSmoke trims a long response body down to a chunk that
// is useful for diagnostics without flooding the test output.
func snippetForSmoke(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
