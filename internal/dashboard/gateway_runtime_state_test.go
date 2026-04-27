package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// GatewayRunning is the single source of truth for the Gateway page
// status pill AND the green "Routing tool calls" banner. Before
// DP-SMOKE-01 it only checked the legacy child-process pointer
// (s.gwCmd), so the in-process gateway path used by `oktsec run`
// rendered the page in a contradictory state — status "offline",
// port "Listening on Port 9091", banner "Routing tool calls"
// — even when the gateway was actually serving traffic.
//
// This test pins the new contract: when the in-process readiness
// callback has fired (SetGatewayManaged()), GatewayRunning() must
// return true AND the rendered banner must read as "Routing".
func TestGatewayRuntimeState_InProcessReadyShowsRouting(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = true
	srv.SetGatewayManaged() // simulates the readiness callback firing post-bind

	if !srv.GatewayRunning() {
		t.Fatal("GatewayRunning must return true when SetGatewayManaged has fired")
	}

	body := getGatewayPage(t, srv)
	if !strings.Contains(body, "Routing tool calls through Oktsec") {
		t.Errorf("in-process ready gateway must render the green Routing banner; body lacks it")
	}
	if strings.Contains(body, "not yet listening") {
		t.Error("in-process ready gateway must NOT show the 'not yet listening' banner")
	}
	if strings.Contains(body, "Gateway is disabled") {
		t.Error("in-process ready gateway must NOT show the disabled banner")
	}
}

// Enabled but the readiness callback has not fired (NewGateway
// failure, bind failure, or just race-window before bind): the
// page must show the amber "enabled but not yet listening"
// banner, not the green "Routing" banner. The status pill and
// banner must agree.
func TestGatewayRuntimeState_EnabledButNotLiveShowsAmber(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = true
	// Deliberately do NOT call SetGatewayManaged.

	if srv.GatewayRunning() {
		t.Fatal("GatewayRunning must return false when no readiness callback fired and no child process exists")
	}

	body := getGatewayPage(t, srv)
	if !strings.Contains(body, "not yet listening") {
		t.Errorf("enabled-but-not-live gateway must render the 'not yet listening' banner; body lacks it")
	}
	if strings.Contains(body, "Routing tool calls through Oktsec") {
		t.Error("enabled-but-not-live gateway must NOT show the green Routing banner")
	}
}

// Disabled gateway: amber disabled banner, no green Routing,
// no "not yet listening" (which only applies to enabled-but-not-
// live). Three-way state check that keeps the banner contract
// from collapsing back into a binary enabled/disabled flag.
func TestGatewayRuntimeState_DisabledShowsDisabledBanner(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = false

	if srv.GatewayRunning() {
		t.Fatal("GatewayRunning must return false when gateway is disabled")
	}

	body := getGatewayPage(t, srv)
	if !strings.Contains(body, "Gateway is disabled") {
		t.Errorf("disabled gateway must render the disabled banner; body lacks it")
	}
	if strings.Contains(body, "Routing tool calls through Oktsec") {
		t.Error("disabled gateway must NOT show the green Routing banner")
	}
	if strings.Contains(body, "not yet listening") {
		t.Error("disabled gateway must NOT show the 'not yet listening' banner")
	}
}

// /dashboard/api/gateway/health is the HTMX partial that drives the
// status pill in the corner of the Gateway card. It used to check
// only the child-process pointer and would render "offline" while
// the in-process gateway was actually serving. This test pins that
// the partial agrees with the page-level Routing banner.
func TestGatewayRuntimeState_HealthEndpointAgreesWithBanner(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = true
	srv.SetGatewayManaged()
	// One configured backend so the partial does not short-circuit
	// with the "no backends" warning.
	if srv.cfg.MCPServers == nil {
		srv.cfg.MCPServers = map[string]config.MCPServerConfig{}
	}
	srv.cfg.MCPServers["echo"] = config.MCPServerConfig{Transport: "stdio", Command: "true"}

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/gateway/health", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, ">online<") {
		t.Errorf("health partial must read 'online' when in-process gateway is ready; body = %s", body)
	}
}

// getGatewayPage renders /dashboard/gateway with an authenticated
// session and returns the body. Small helper so the four state
// tests above stay focused on assertions rather than wiring.
func getGatewayPage(t *testing.T, srv *Server) string {
	t.Helper()
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/gateway", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/dashboard/gateway status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}
