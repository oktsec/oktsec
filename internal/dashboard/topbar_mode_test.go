package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// Every dashboard page renders the shared topbar mode pill from the
// .RequireSig template field. If a handler forgets to populate that
// field, Go's zero-value (false) makes the pill read "observe" even
// when the live config has require_signature: true. That visual
// inconsistency was the DP-01 desktop blocker — Sessions/AI/Gateway
// could read "observe" while Overview/Alerts/Settings read "enforce"
// for the same config.
//
// The list below is the page-route inventory the topbar covers.
// Routes that take a path parameter (event detail, agent detail,
// rule detail, session trace, MCP server detail) are exercised
// separately when the prerequisites are seeded; everything else
// runs against a fresh test server.
var topbarPageRoutes = []string{
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

// 1. With require_signature: true on the config, every page must
// render the enforce pill. A handler that forgets to thread
// RequireSig flips its pill back to observe and contradicts the
// rest of the dashboard for the same config.
func TestTopbarMode_AllPagesAgreeWithConfigEnforce(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.RequireSignature = true

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	for _, path := range topbarPageRoutes {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rr.Code)
			}
			body := rr.Body.String()
			// Mode pill markup: class names "enforce" / "observe"
			// land on the same element. Asserting the enforce class
			// catches both a missing RequireSig (defaults to observe)
			// and a layout regression that drops the pill entirely.
			if !strings.Contains(body, `class="mode-pill enforce"`) {
				t.Errorf("topbar must show enforce pill when require_signature=true; body class missing on %s", path)
			}
			if strings.Contains(body, `class="mode-pill observe"`) {
				t.Errorf("topbar must NOT show observe pill when require_signature=true on %s", path)
			}
		})
	}
}

// 2. With require_signature: false (the default) every page renders
// the observe pill. The mirror of test #1 — together they pin the
// bidirectional contract.
func TestTopbarMode_AllPagesAgreeWithConfigObserve(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.RequireSignature = false

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	for _, path := range topbarPageRoutes {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rr.Code)
			}
			body := rr.Body.String()
			if !strings.Contains(body, `class="mode-pill observe"`) {
				t.Errorf("topbar must show observe pill when require_signature=false on %s", path)
			}
			if strings.Contains(body, `class="mode-pill enforce"`) {
				t.Errorf("topbar must NOT show enforce pill when require_signature=false on %s", path)
			}
		})
	}
}

// 3. Gateway page label switches between "Listening on" and
// "Configured port" based on whether the dashboard has
// authoritative knowledge of the live listener. When the gateway
// runs in-process (oktsec run) the dashboard shares the cfg
// pointer the gateway mutates after binding, so the port is live.
// When the dashboard spawns the gateway as a child process (or the
// gateway runs standalone) the dashboard only knows the configured
// value — auto-increment via netutil.ListenAutoPort can have moved
// the actual listener to a different port, so the label must drop
// to "Configured port" instead of misleading the operator.
func TestGatewayPage_PortLabelHonorsLiveOrConfigured(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = true
	srv.cfg.Gateway.Port = 9090

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/dashboard/gateway", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		return rr.Body.String()
	}

	// Default test server: gwManaged=false → child-process / unknown.
	// Label must read "Configured Port".
	body := get()
	if !strings.Contains(body, "Configured Port") {
		t.Errorf("expected Configured Port label when gwManaged=false; body lacks it")
	}
	if strings.Contains(body, "Listening on") {
		t.Errorf("must not claim Listening on when gwManaged=false (port may not be live)")
	}

	// Flip to in-process: dashboard now shares the cfg pointer the
	// gateway mutates with the actual port, so the label reflects
	// a live listener.
	srv.SetGatewayManaged()
	body = get()
	if !strings.Contains(body, "Listening on") {
		t.Errorf("expected Listening on label when gwManaged=true; body lacks it")
	}
}

// 3b. NewServer must NOT auto-spawn a child gateway during
// construction. The previous behavior fired before any caller
// could call SetGatewayManaged, so `oktsec run` ended up with two
// gateways racing for the same port (the dashboard's child plus
// the in-process gateway run.go starts moments later). Regression
// guard: with Gateway.Enabled and at least one MCPServer
// configured, gwCmd must remain nil after NewServer returns.
func TestNewServer_DoesNotAutoSpawnChildGateway(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = true
	srv.cfg.MCPServers = map[string]config.MCPServerConfig{
		"echo": {Transport: "stdio", Command: "true"},
	}
	// Re-construct now that the conditions are set, to exercise the
	// construction path callers actually hit.
	srv2 := NewServer(srv.cfg, "", srv.audit, srv.keys, srv.scanner, srv.logger)
	srv2.gwMu.Lock()
	cmd := srv2.gwCmd
	srv2.gwMu.Unlock()
	if cmd != nil {
		t.Errorf("NewServer auto-spawned a child gateway (gwCmd=%+v); construction must be side-effect-free", cmd)
	}
}

// 4. The dashboard can render the same page twice in a row without
// flipping its mode pill. Catches a regression where a handler
// reads RequireSig from a stale snapshot instead of the live cfg.
func TestTopbarMode_SecondRenderMatchesFirst(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.RequireSignature = true
	srv.cfg.Agents["a1"] = config.Agent{}

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	render := func() string {
		req := httptest.NewRequest(http.MethodGet, "/dashboard/agents", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Body.String()
	}
	first := strings.Contains(render(), `class="mode-pill enforce"`)
	second := strings.Contains(render(), `class="mode-pill enforce"`)
	if first != second {
		t.Errorf("topbar mode flipped between renders: first=%v second=%v", first, second)
	}
}
