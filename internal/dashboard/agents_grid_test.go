package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// The Agents page used a fixed two-column grid
// (grid-template-columns: 1fr 1fr). With one configured agent the
// right column rendered as a large empty gray panel — the
// DP-SMOKE-03 walkthrough finding. The fix switches to
// `repeat(auto-fit, minmax(320px, 1fr))` so a single agent fills
// the row instead of stranding an empty track.
//
// This test pins both halves of the new contract: the grid must
// use the auto-fit form, AND the legacy 1fr 1fr form (or the
// 768px-only collapse media query that paired with it) must not
// reappear.
func TestAgentsGrid_UsesAutoFit(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents["solo-agent"] = config.Agent{}

	body := getAgentsPage(t, srv)

	if !strings.Contains(body, "grid-template-columns:repeat(auto-fit,minmax(320px,1fr))") {
		t.Errorf("Agents page must use auto-fit grid so a single card fills the row; body lacks it")
	}
	if strings.Contains(body, "grid-template-columns:1fr 1fr") {
		t.Errorf("Agents page must not reintroduce the fixed two-column grid that left a blank panel for solo agents")
	}
}

// A populated Agents page with multiple agents must still render
// every card. The auto-fit grid does not change card structure;
// this test guards against an accidental template change that
// drops the loop.
func TestAgentsGrid_RendersEveryConfiguredAgent(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents["alpha"] = config.Agent{}
	srv.cfg.Agents["beta"] = config.Agent{}
	srv.cfg.Agents["gamma"] = config.Agent{}

	body := getAgentsPage(t, srv)
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(body, name) {
			t.Errorf("Agents page must render configured agent %q; body lacks it", name)
		}
	}
}

func getAgentsPage(t *testing.T, srv *Server) string {
	t.Helper()
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/agents", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/dashboard/agents status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}
