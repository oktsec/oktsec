package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// 9. Coverage cells must activate on Enter and Space, not just mouse
// click. tabindex=0 + role=button only makes a <td> focusable;
// browsers do not synthesize click on Enter/Space for non-button
// elements, so the hx-trigger must spell out the keyboard events
// explicitly. Regression guard for keyboard-only operators (and
// screen readers) being unable to open the drawer.
func TestOverview_CoverageCellsActivateOnKeyboard(t *testing.T) {
	srv := newTestServer(t)
	seedPrincipalWithGatewayBearer(srv, "local-codex")

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	// HTMX trigger spec: comma-separated event filters. Enter and
	// Space both must be present so keyboard activation works.
	wantTrigger := `hx-trigger="click, keyup[key=='Enter'], keyup[key==' ']"`
	hits := strings.Count(body, wantTrigger)
	// One per (principal, surface) cell — three surfaces, one principal.
	if hits != 3 {
		t.Errorf("hx-trigger keyboard wiring count = %d; want 3 (one per surface column)", hits)
	}
}

// 10. connector_id is a derived filter (not a persisted column on
// activity_events). The handler must query the store WITHOUT a
// connector_id constraint and then post-filter by the connector
// derived from each event's principal. Regression guard for the
// original bug where connector_id was passed straight through to
// activity.Query and matched zero rows because surface adapters
// never populate Event.ConnectorID.
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
