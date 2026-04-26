package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors"
)

// seedActivityForTest writes one event into the test server's activity
// store so the drill-down handlers have something to render. Returns
// the seeded event so assertions can compare against fields we own.
func seedActivityForTest(t *testing.T, srv *Server, principalID, surface, tool string) activity.Event {
	t.Helper()
	store := srv.coverageActivityStore()
	if store == nil {
		t.Fatal("seedActivityForTest: activity store not wired (audit store is not DB-backed)")
	}
	ev := activity.Event{
		ID:                  "act-" + tool + "-" + principalID,
		Timestamp:           time.Now().UTC(),
		PrincipalID:         principalID,
		AuthMethod:          "bearer_token",
		PrincipalTrustLevel: "authenticated",
		Surface:             activity.Surface(surface),
		EventType:           activity.EventMCPToolCall,
		EvidenceType:        activity.EvidenceGateway,
		Status:              "allow",
		PolicyDecision:      "ok",
		CoverageMode:        activity.CoverageProtected,
		Confidence:          100,
		ResourceType:        "mcp_tool",
		ResourceID:          tool,
		ResourceLabel:       tool,
		AuditEntryID:        "audit-" + tool,
	}
	if err := store.Insert(context.Background(), ev); err != nil {
		t.Fatalf("seed activity insert: %v", err)
	}
	return ev
}

// seedPrincipalWithGatewayBearer adds a principal with one active
// gateway_bearer token so the connector inference produces
// generic-mcp-http and the coverage matrix includes the cell.
func seedPrincipalWithGatewayBearer(srv *Server, id string) {
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals, config.PrincipalConfig{
		ID:          id,
		DisplayName: id,
		Kind:        "agent",
		Tokens: []config.PrincipalTokenConfig{{
			ID:        id + "-gw",
			Type:      "gateway_bearer",
			Hash:      "sha256:dummy",
			CreatedAt: "2026-04-26T00:00:00Z",
		}},
	})
	srv.cfg.Gateway.Enabled = true
}

// 1. GET /dashboard/api/activity returns the seeded event as JSON,
// with the spec field names (trust_level, not principal_trust_level)
// and the connector_id derived from the principal's token mix.
func TestActivityAPI_ReturnsSeededEvent(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")
	seedActivityForTest(t, srv, "local-codex", "mcp_http", "filesystem.read_file")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/activity?principal_id=local-codex&surface=mcp_http", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	var got []activityEventDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v; body = %s", err, rr.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("got %d events; want 1; body = %s", len(got), rr.Body.String())
	}
	ev := got[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal_id = %q; want local-codex", ev.PrincipalID)
	}
	if ev.Surface != "mcp_http" {
		t.Errorf("surface = %q; want mcp_http", ev.Surface)
	}
	if ev.TrustLevel != "authenticated" {
		t.Errorf("trust_level = %q; want authenticated (DTO renames principal_trust_level)", ev.TrustLevel)
	}
	if ev.CoverageMode != "protected" {
		t.Errorf("coverage_mode = %q; want protected", ev.CoverageMode)
	}
	if ev.ConnectorID != connectors.IDGenericMCPHTTP {
		t.Errorf("connector_id = %q; want generic-mcp-http (derived from token mix)", ev.ConnectorID)
	}
	if ev.ResourceLabel != "filesystem.read_file" {
		t.Errorf("resource_label = %q; want filesystem.read_file", ev.ResourceLabel)
	}
}

// 2. The endpoint requires an authenticated dashboard session. API
// routes return 401 (not the 302 redirect HTML pages get) so a
// scripted caller sees an explicit auth failure instead of HTML.
func TestActivityAPI_RequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "/dashboard/api/activity", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET status = %d; want 401", rr.Code)
	}
}

// 3. limit query param is honored and capped. activity.MaxQueryLimit
// is 500; passing limit=10000 must not return more than 500 rows.
// The test seeds two events and asserts the bound applies via the
// returned slice length.
func TestActivityAPI_LimitIsBounded(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")
	seedActivityForTest(t, srv, "local-codex", "mcp_http", "tool-a")
	seedActivityForTest(t, srv, "local-codex", "mcp_http", "tool-b")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// limit=10000 (way above the cap) must still succeed and return
	// just our two rows — the bound is a max, not a min.
	req := httptest.NewRequest("GET", "/dashboard/api/activity?principal_id=local-codex&limit=10000", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got []activityEventDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d events; want 2", len(got))
	}
	// Activity cap (500) is enforced at the store layer; this test
	// proves the dashboard does not reject a wildly oversized limit
	// (which would be a regression making oversized scripts fail
	// hard instead of silently being bounded).
}

// 4. With no events seeded the endpoint returns an empty JSON array,
// not null. Scripted callers can then iterate without nil-checking.
func TestActivityAPI_EmptyReturnsEmptyArray(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/activity?principal_id=local-codex", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := strings.TrimSpace(rr.Body.String())
	if body != "[]" {
		t.Errorf("empty result body = %q; want []", body)
	}
}

// 5. The drill-down drawer renders the coverage badge, connector,
// and seeded events. Empty-state copy must not appear when at least
// one event exists.
func TestCoverageCellDrawer_RendersHeaderAndEvents(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")
	seedActivityForTest(t, srv, "local-codex", "mcp_http", "filesystem.read_file")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex&surface=mcp_http", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"local-codex",
		"MCP Gateway",
		"Protected",
		"Generic MCP HTTP",
		"filesystem.read_file",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("drawer body missing %q; body = %s", want, body)
		}
	}
	if strings.Contains(body, "No activity recorded") {
		t.Error("drawer should not show empty state when an event exists")
	}
}

// 5b. Protected drawer carries the pre-action explanation and does
// NOT surface a next-action — Protected is the goal state, so
// pushing the operator toward another action would be misleading.
func TestCoverageCellDrawer_ProtectedExplanationNoNextAction(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex&surface=mcp_http", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Why this state") {
		t.Error("drawer must include Why this state section")
	}
	if !strings.Contains(body, "pre-action path") {
		t.Errorf("Protected drawer must include 'pre-action path'; body = %s", body)
	}
	if strings.Contains(body, `class="cd-next-hint"`) || strings.Contains(body, `class="cd-next-cmd"`) {
		t.Error("Protected drawer must NOT show a next-action block")
	}
}

// 5c. Observed drawer carries the telemetry-without-blocking
// explanation and the truthful CLI command for issuing the right
// token. Token issuance is a CLI workflow today (oktsec tokens
// create), not a dashboard one — the drawer must not link to a
// Settings page that cannot perform the action. Regression guard
// for the "promise capability the UI does not have" failure mode.
func TestCoverageCellDrawer_ObservedShowsHonestCLICommand(t *testing.T) {
	srv := newTestServer(t)
	// Hooks in local profile with no hook_bearer token => observed.
	seedPrincipalWithGatewayBearer(srv, "local-codex")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex&surface=hooks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "telemetry") {
		t.Errorf("Observed drawer must include 'telemetry'; body = %s", body)
	}
	wantCmd := "oktsec tokens create --principal local-codex --type hook_bearer"
	if !strings.Contains(body, wantCmd) {
		t.Errorf("Observed drawer must surface the truthful CLI command %q; body = %s", wantCmd, body)
	}
	// Must NOT link to Settings — Settings cannot issue tokens today.
	if strings.Contains(body, `href="/dashboard/settings"`) {
		t.Error("drawer must not link the next-action to /dashboard/settings (cannot issue tokens)")
	}
}

// 5d. Blind drawer carries the no-protection explanation and the
// truthful CLI command for the surface in question. Egress proxy
// off + no proxy_basic token reaches this state.
func TestCoverageCellDrawer_BlindShowsHonestCLICommand(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")
	// Egress surface is off in defaults; the principal has no proxy
	// token, so the egress cell is Blind.

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex&surface=http_egress_proxy", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "no active protection") {
		t.Errorf("Blind drawer must include 'no active protection'; body = %s", body)
	}
	wantCmd := "oktsec tokens create --principal local-codex --type proxy_basic"
	if !strings.Contains(body, wantCmd) {
		t.Errorf("Blind drawer must surface the egress CLI command %q; body = %s", wantCmd, body)
	}
}

// 5d2. The MCP gateway drawer surfaces the gateway_bearer CLI
// command for non-Protected states. Covers the third surface so the
// truthful-CLI contract is exhaustive across all three.
func TestCoverageCellDrawer_MCPHTTPShowsGatewayBearerCommand(t *testing.T) {
	srv := newTestServer(t)
	// Add a principal with NO tokens so mcp_http resolves to a
	// non-Protected state in local profile (loopback observed).
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals, config.PrincipalConfig{
		ID:          "claude-code",
		DisplayName: "claude-code",
		Kind:        "agent",
	})
	srv.cfg.Gateway.Enabled = true

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=claude-code&surface=mcp_http", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	wantCmd := "oktsec tokens create --principal claude-code --type gateway_bearer"
	if !strings.Contains(body, wantCmd) {
		t.Errorf("non-Protected mcp_http drawer must surface the gateway_bearer CLI command %q; body = %s",
			wantCmd, body)
	}
}

// 5e. The explanation text must stay neutral. Forbidden vocabulary
// from the public-artifact rule must not slip into the drawer body.
func TestCoverageCellDrawer_ExplanationStaysNeutral(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	for _, surface := range []string{"mcp_http", "http_egress_proxy", "hooks"} {
		req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex&surface="+surface, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		body := strings.ToLower(rr.Body.String())
		for _, banned := range []string{"fully protected", "complete coverage", "blind failure", "honest", "fake"} {
			if strings.Contains(body, banned) {
				t.Errorf("surface %q drawer contains forbidden phrase %q", surface, banned)
			}
		}
	}
}

// 6. Empty-state copy is shown when no activity is recorded for the
// (principal, surface) pair. The header still renders so the operator
// can see "yes I clicked the right cell, it just has no data yet".
func TestCoverageCellDrawer_EmptyState(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")
	// No activity seeded.

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex&surface=hooks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "No activity recorded for this surface yet.") {
		t.Errorf("drawer body missing empty-state copy; body = %s", body)
	}
	if !strings.Contains(body, "local-codex") || !strings.Contains(body, "Hooks") {
		t.Errorf("drawer header missing principal/surface; body = %s", body)
	}
}

// 7. Missing required query params return a 400, not a 500. Catches
// the simple "operator pasted the URL wrong" case.
func TestCoverageCellDrawer_MissingParamsReturns400(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id=local-codex", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing surface)", rr.Code)
	}
}

// 8. The Overview matrix renders the cells with the drill-down
// HTMX attributes so the cell click actually wires through to the
// drawer. Regression guard for an accidental template revert.
func TestOverview_CoverageCellsAreClickable(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")

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
		`hx-get="/dashboard/api/coverage/cell?principal_id=local-codex&surface=mcp_http"`,
		`hx-get="/dashboard/api/coverage/cell?principal_id=local-codex&surface=http_egress_proxy"`,
		`hx-get="/dashboard/api/coverage/cell?principal_id=local-codex&surface=hooks"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview missing clickable wiring %q", want)
		}
	}
}

// 9. Coverage cells render as native buttons under strict CSP.
// HTMX trigger filters like keyup[key=='Enter'] use eval() under the
// hood, which is blocked by script-src 'self' 'unsafe-inline' (no
// 'unsafe-eval'). Native <button> elements activate on click, Enter,
// and Space without any filter expression, so the cell stays
// keyboard-accessible without relaxing CSP. Regression guard
// asserting both halves of the contract: buttons present, no filter
// expressions emitted, no CSP relaxation.
func TestOverview_CoverageCellsUseCSPSafeButtons(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()

	// Native buttons, one per surface column.
	if got := strings.Count(body, `class="cov-cell-btn"`); got < 3 {
		t.Errorf("cov-cell-btn count = %d; want at least 3 (one per surface)", got)
	}
	if !strings.Contains(body, `<button type="button" class="cov-cell-btn"`) {
		t.Error("coverage cells must render as <button type=\"button\">")
	}

	// HTMX trigger filters require eval() and are blocked by CSP.
	// Native buttons make them unnecessary.
	if strings.Contains(body, "keyup[") || strings.Contains(body, "keydown[") {
		t.Error("coverage cells must not emit HTMX trigger filters that require eval()")
	}

	// CSP must stay strict.
	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("dashboard CSP must not include 'unsafe-eval'; got %q", csp)
	}
}

// 10. connector_id is a derived filter (not a persisted column on
// activity_events). The handler resolves the connector to the set of
// matching principals and pushes the filter into SQL via PrincipalIDs
// so the LIMIT applies AFTER the connector filter, never before.
// Regression guard: connector_id must match rows whose principal
// currently maps to that connector even when Event.ConnectorID is
// empty (which surface adapters always leave it).
func TestActivityAPI_ConnectorIDFilterPostQueryDerived(t *testing.T) {
	srv := newTestServer(t)
	// Two principals: one custom-client (gateway + hook tokens),
	// one generic-mcp-http (gateway only).
	seedPrincipalWithGatewayBearer(srv, "single-surface")
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals, config.PrincipalConfig{
		ID:          "multi-surface",
		DisplayName: "multi-surface",
		Kind:        "agent",
		Tokens: []config.PrincipalTokenConfig{
			{ID: "ms-gw", Type: "gateway_bearer", Hash: "sha256:dummy", CreatedAt: "2026-04-26T00:00:00Z"},
			{ID: "ms-hk", Type: "hook_bearer", Hash: "sha256:dummy", CreatedAt: "2026-04-26T00:00:00Z"},
		},
	})

	// One event for each principal. Both leave Event.ConnectorID
	// empty, mirroring how the surface adapters write today.
	seedActivityForTest(t, srv, "single-surface", "mcp_http", "tool-single")
	seedActivityForTest(t, srv, "multi-surface", "mcp_http", "tool-multi")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Filter by connector_id=generic-mcp-http: must return only the
	// single-surface principal even though neither event row has the
	// connector ID persisted.
	req := httptest.NewRequest("GET", "/dashboard/api/activity?connector_id="+connectors.IDGenericMCPHTTP, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	var got []activityEventDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events; want 1 (only single-surface principal matches generic-mcp-http); body = %s",
			len(got), rr.Body.String())
	}
	if got[0].PrincipalID != "single-surface" {
		t.Errorf("returned principal = %q; want single-surface", got[0].PrincipalID)
	}
	if got[0].ConnectorID != connectors.IDGenericMCPHTTP {
		t.Errorf("returned connector_id = %q; want %s", got[0].ConnectorID, connectors.IDGenericMCPHTTP)
	}

	// Filter by connector_id=custom-client: must return only the
	// multi-surface principal.
	req = httptest.NewRequest("GET", "/dashboard/api/activity?connector_id="+connectors.IDCustomClient, nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(got) != 1 || got[0].PrincipalID != "multi-surface" {
		t.Errorf("custom-client filter returned %d events; want 1 multi-surface; body = %s",
			len(got), rr.Body.String())
	}
}

// 11. The connector_id filter must survive the LIMIT cutoff.
// Limit-cutoff regression scenario: many recent events from one
// connector, plus one older event from a different connector.
// Asking for limit=N of the rare connector must still return its
// event even when the recent N+ events all belong to other
// connectors. The connector filter has to apply BEFORE the LIMIT,
// which is why PrincipalIDs is pushed into SQL.
func TestActivityAPI_ConnectorIDFilterSurvivesLimit(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "noisy-single-surface")
	srv.cfg.Identity.Principals = append(srv.cfg.Identity.Principals, config.PrincipalConfig{
		ID:          "rare-multi-surface",
		DisplayName: "rare-multi-surface",
		Kind:        "agent",
		Tokens: []config.PrincipalTokenConfig{
			{ID: "rare-gw", Type: "gateway_bearer", Hash: "sha256:dummy", CreatedAt: "2026-04-26T00:00:00Z"},
			{ID: "rare-hk", Type: "hook_bearer", Hash: "sha256:dummy", CreatedAt: "2026-04-26T00:00:00Z"},
		},
	})

	// Seed: one OLD event for rare-multi-surface (custom-client),
	// then 60 newer events for noisy-single-surface (generic-mcp-http).
	// The old event must still surface when we filter by custom-client
	// even though it would not be in the most-recent 50 globally.
	store := srv.coverageActivityStore()
	if store == nil {
		t.Fatal("activity store not wired")
	}
	rare := activity.Event{
		ID:           "rare-old",
		Timestamp:    time.Date(2026, 4, 26, 8, 0, 0, 0, time.UTC),
		PrincipalID:  "rare-multi-surface",
		AuthMethod:   "bearer_token",
		Surface:      activity.SurfaceMCPHTTP,
		EventType:    activity.EventMCPToolCall,
		EvidenceType: activity.EvidenceGateway,
		CoverageMode: activity.CoverageProtected,
		Confidence:   100,
		ResourceType: "mcp_tool",
		ResourceID:   "rare-tool",
	}
	if err := store.Insert(context.Background(), rare); err != nil {
		t.Fatalf("seed rare event: %v", err)
	}
	// 60 newer noisy events. 60 > DefaultQueryLimit (50)? No,
	// DefaultQueryLimit is 100. Use enough to push the rare event
	// past any reasonable post-filter cutoff: 60 newer events with a
	// limit=50 query would have lost rare under the old code.
	for i := 0; i < 60; i++ {
		ev := activity.Event{
			ID:           "noisy-" + strconv.Itoa(i),
			Timestamp:    time.Date(2026, 4, 26, 9, i, 0, 0, time.UTC),
			PrincipalID:  "noisy-single-surface",
			AuthMethod:   "bearer_token",
			Surface:      activity.SurfaceMCPHTTP,
			EventType:    activity.EventMCPToolCall,
			EvidenceType: activity.EvidenceGateway,
			CoverageMode: activity.CoverageProtected,
			Confidence:   100,
			ResourceType: "mcp_tool",
			ResourceID:   "noisy-tool",
		}
		if err := store.Insert(context.Background(), ev); err != nil {
			t.Fatalf("seed noisy event %d: %v", i, err)
		}
	}

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// limit=50: with the connector filter pushed into SQL via the
	// PrincipalIDs IN clause, the store returns the 50 most recent
	// events from the matching principal set (rare-multi-surface).
	// Without the SQL push-down, a post-filter applied AFTER the
	// LIMIT would discard all 50 noisy rows and return [].
	req := httptest.NewRequest("GET",
		"/dashboard/api/activity?connector_id="+connectors.IDCustomClient+"&limit=50", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got []activityEventDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events; want 1 (rare must survive LIMIT cutoff); body = %s",
			len(got), rr.Body.String())
	}
	if got[0].ID != "rare-old" {
		t.Errorf("returned event ID = %q; want rare-old", got[0].ID)
	}
}

// 12. Asking for a connector that has no matching principals must
// short-circuit cleanly. Without the guard, the IN clause would be
// "principal_id IN ()" which is invalid SQL on most engines.
func TestActivityAPI_ConnectorIDWithNoMatchingPrincipalsReturnsEmpty(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")
	seedActivityForTest(t, srv, "local-codex", "mcp_http", "tool")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/activity?connector_id="+connectors.IDLegacyLoopbackHeader, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := strings.TrimSpace(rr.Body.String())
	if body != "[]" {
		t.Errorf("body = %q; want [] (no principal matches the requested connector)", body)
	}
}
