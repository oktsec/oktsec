package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// The community dashboard is a public repository. UI copy must not
// claim capabilities the product does not have, must not use
// reviewer-attribution wording, and must not reach for marketing
// superlatives the security positioning explicitly avoids. The
// dashboard UX spec hard-bans the strings below; this test pins the
// rule against the rendered Overview body so a future copy edit
// cannot reintroduce a banned phrase without a test failure first.
//
// The list lives here (next to the surface it guards) rather than in
// a shared package so each surface owns its own contract — adding a
// banned term in one place does not silently expand the rule for
// every surface.
var bannedOverviewPhrases = []string{
	// Hard-banned product claims (spec "Avoid public claims").
	"sees all",
	"sees everything",
	"see everything",
	"full coverage",
	"complete coverage",
	"complete protection",
	"complete runtime protection",
	"all agents are protected",
	"fully protected",
	// Unsupported auth/edition features (spec "Truth Constraints").
	"sso",
	"saml",
	"passkey",
	"cloud login",
	"hosted dashboard",
	"admin console",
	// Reviewer attribution / temporal framing the public-artifact
	// rule keeps out of source-rendered HTML.
	"honest",
	"honesty",
	"lying",
	"fabricated",
	"previously",
}

// 1. The Overview empty state must not contain any banned phrase.
// The empty state is the first screen a brand-new operator sees, so
// it is the highest-leverage surface to keep accurate.
func TestPublicArtifactSweep_OverviewEmptyStateStaysAccurate(t *testing.T) {
	srv := newTestServer(t)
	// Default state: zero messages, zero agents — empty state path.
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := strings.ToLower(rr.Body.String())
	for _, banned := range bannedOverviewPhrases {
		if strings.Contains(body, banned) {
			t.Errorf("overview empty-state body contains banned phrase %q", banned)
		}
	}
}

// 2. The Overview populated state (>= 1 message, >= 1 agent) renders
// the live coverage matrix instead of the empty state. The same
// banned-phrase contract applies: the matrix and surrounding cards
// must not reach for marketing superlatives or unsupported-feature
// language.
func TestPublicArtifactSweep_OverviewPopulatedStateStaysAccurate(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals, config.PrincipalConfig{
		ID:          "local-codex",
		DisplayName: "local-codex",
		Kind:        "agent",
		Tokens: []config.PrincipalTokenConfig{{
			ID: "gw1", Type: "gateway_bearer", Hash: "sha256:dummy",
			CreatedAt: "2026-04-26T00:00:00Z",
		}},
	})
	srv.cfg.Gateway.Enabled = true
	// One agent in the agents map flips Overview off the empty state.
	srv.cfg.Agents["local-codex"] = config.Agent{}

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := strings.ToLower(rr.Body.String())
	for _, banned := range bannedOverviewPhrases {
		if strings.Contains(body, banned) {
			t.Errorf("overview populated-state body contains banned phrase %q", banned)
		}
	}
}

// 3. The empty-state rule count must be the live count from the
// scanner, not a stale literal. A bare regex for "230 detection
// rules" guards the most recent drift; if the empty-state copy
// reverts to a hardcoded number this test fires.
func TestPublicArtifactSweep_EmptyStateRuleCountIsLive(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, stale := range []string{"230 detection rules", "230 rules"} {
		if strings.Contains(body, stale) {
			t.Errorf("empty state shows stale literal rule count %q; should be {{.RuleCount}}", stale)
		}
	}
}
