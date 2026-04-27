package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

// On a fresh dashboard with no audit traffic, the Overview hourly
// sparkline used to render as 24 zero-height bars inside an
// unlabelled container — visible on desktop walkthroughs as a
// standalone blue strip with no context. DP-SMOKE-02. The fix:
// getHourlyChart returns nil when the maximum bucket count is 0,
// and the template's `{{if .Chart}}` skips the section.
func TestOverviewSparkline_SuppressedWithoutTraffic(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents["smoke-agent"] = config.Agent{}
	// Deliberately do not log any audit entries.

	body := getOverviewBody(t, srv)
	if strings.Contains(body, `class="sparkline-chart"`) {
		t.Errorf("Overview must not render the sparkline when no audit traffic exists; body contains sparkline-chart")
	}
	if strings.Contains(body, "Hourly activity (last 24h)") {
		t.Errorf("Overview must not render the Hourly activity heading when there is no traffic to chart")
	}
}

// When the sparkline does render (real traffic in at least one
// hour bucket) it must be wrapped in a labelled card so it carries
// visible context. The label "Hourly activity (last 24h)" is the
// stable contract; the bars themselves still come from the
// sparkline-chart container the CSS targets.
func TestOverviewSparkline_LabelledCardWhenDataExists(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Agents["smoke-agent"] = config.Agent{}

	// Log one real audit entry so QueryHourlyStats has data.
	srv.audit.Log(audit.Entry{
		ID:             "smoke-1",
		Timestamp:      "2026-04-27T10:00:00Z",
		FromAgent:      "smoke-agent",
		ToAgent:        "echo",
		ContentHash:    "h",
		Status:         audit.StatusDelivered,
		PolicyDecision: "allow",
	})
	srv.audit.Flush()

	body := getOverviewBody(t, srv)
	if !strings.Contains(body, `class="sparkline-chart"`) {
		t.Fatal("Overview must render the sparkline when audit traffic exists; body lacks sparkline-chart")
	}
	if !strings.Contains(body, "Hourly activity (last 24h)") {
		t.Errorf("Overview sparkline must carry the labelled card heading; body lacks 'Hourly activity'")
	}
}

// getOverviewBody renders /dashboard with an authenticated session
// and returns the body. The Overview empty state hides the matrix
// when there are zero agents AND zero messages; both sparkline
// tests configure at least one agent so the populated layout
// (and the sparkline section) is reachable.
func getOverviewBody(t *testing.T, srv *Server) string {
	t.Helper()
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/dashboard status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}
