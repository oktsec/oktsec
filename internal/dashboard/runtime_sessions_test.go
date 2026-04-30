package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/runtime"
)

// runtime_sessions_test.go covers the Phase 3C full slice. The
// shared scaffolding is newRuntimeGraphTestServer + seedRuntimeEvent
// from runtime_graph_test.go: a temp-dir server with both an audit
// store and a runtime store wired, and a helper that pushes one
// hook event through Normalize+RecordHook so the runtime tables
// fill the same way the production hooks handler would. Tests
// here only need to declare what to seed and what to assert.

// fetchSessionsHTML returns the rendered Sessions list HTML for
// the given range token.
func fetchSessionsHTML(t *testing.T, srv *Server, cookie *http.Cookie, handler http.Handler, rng string) string {
	t.Helper()
	url := "/dashboard/sessions"
	if rng != "" {
		url += "?range=" + rng
	}
	req := httptest.NewRequest("GET", url, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sessions list status = %d, body=%s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// fetchSessionDetailHTML returns the rendered detail HTML for one
// session id.
func fetchSessionDetailHTML(t *testing.T, srv *Server, cookie *http.Cookie, handler http.Handler, sessionID string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/dashboard/sessions/"+sessionID, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// fetchSessionExport returns the raw response for one session
// export endpoint (json, csv, etc.).
func fetchSessionExport(t *testing.T, cookie *http.Cookie, handler http.Handler, sessionID, format string) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequest("GET", "/dashboard/api/session/"+sessionID+"/"+format, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code, w.Body.String(), w.Result().Header
}

// TestSessions_RuntimePreferredOverAudit — when both runtime and
// audit have rows for a window, the rendered list comes from
// runtime. We assert by looking for the runtime-only header
// columns ("Principal", "Client") that the legacy template never
// produces.
func TestSessions_RuntimePreferredOverAudit(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	// Runtime evidence: one root + one tool call.
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-prefer"}`,
		"sess-prefer", "local-codex", now.Add(-10*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-prefer","tool_name":"Read","tool_use_id":"u1"}`,
		"sess-prefer", "local-codex", now.Add(-9*time.Minute), runtime.OutcomeRefs{Status: "delivered"})

	// Audit evidence for a different session id — should NOT
	// surface because runtime has rows in this window.
	auditStore.Log(audit.Entry{
		ID: "audit-only", Timestamp: now.Add(-8 * time.Minute).Format(time.RFC3339),
		FromAgent: "phantom-agent", ToAgent: "echo", Status: "delivered", PolicyDecision: "allow",
		SessionID: "audit-phantom",
	})
	auditStore.Flush()

	body := fetchSessionsHTML(t, srv, cookie, handler, "24h")
	if !strings.Contains(body, "sess-prefer") {
		t.Errorf("runtime session id missing from list; body=%.300s", body)
	}
	if strings.Contains(body, "audit-phantom") {
		t.Errorf("audit-only session leaked into runtime-preferred view")
	}
	// Runtime template signature columns:
	if !strings.Contains(body, ">Principal<") || !strings.Contains(body, ">Client<") {
		t.Errorf("runtime template chrome missing — handler may not have picked the runtime branch")
	}
}

// TestSessions_FallbacksToAuditWhenRuntimeEmpty — with no runtime
// rows in the window, the legacy audit list still renders. We
// assert by looking for an audit-only column ("Risk") that the
// runtime template does not produce.
func TestSessions_FallbacksToAuditWhenRuntimeEmpty(t *testing.T) {
	srv, _, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	auditStore.Log(audit.Entry{
		ID: "audit-fallback", Timestamp: now.Add(-5 * time.Minute).Format(time.RFC3339),
		FromAgent: "agent-a", ToAgent: "agent-b", Status: "delivered", PolicyDecision: "allow",
		SessionID: "audit-fallback-session",
	})
	auditStore.Flush()

	body := fetchSessionsHTML(t, srv, cookie, handler, "24h")
	if !strings.Contains(body, ">Risk<") {
		t.Errorf("audit template signature missing; runtime branch may have hijacked the empty-runtime case")
	}
	if !strings.Contains(body, "audit-fallback-session") {
		t.Errorf("audit fallback row missing from list")
	}
}

// TestSessions_HeartbeatOnlyRowIsDiagnostic — a heartbeat-prefixed
// session id renders as a diagnostic row: muted styling, zero
// tool count, no threat badge, "Diagnostic heartbeat" label.
func TestSessions_HeartbeatOnlyRowIsDiagnostic(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026-04-30"}`,
		"heartbeat-2026-04-30", "local-codex", now.Add(-3*time.Minute), runtime.OutcomeRefs{})

	body := fetchSessionsHTML(t, srv, cookie, handler, "24h")
	if !strings.Contains(body, "Diagnostic heartbeat") {
		t.Errorf("expected 'Diagnostic heartbeat' label; body=%.400s", body)
	}
	if !strings.Contains(body, `class="ss-heartbeat`) {
		t.Errorf("expected ss-heartbeat row class for muted styling; body=%.400s", body)
	}
	// The threat badge markup is `<span class="ss-threat">N blocked</span>`.
	// A heartbeat-only row must not render that span.
	if strings.Contains(body, `class="ss-threat">`) {
		t.Errorf("heartbeat-only row produced a threat badge")
	}
}

// TestSessions_ActiveNoToolsShowsWaitingState — an active session
// (no EndedAt) with zero tool events renders the neutral
// "Waiting for first tool call" copy instead of an empty cell or
// a threat label.
func TestSessions_ActiveNoToolsShowsWaitingState(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	// Only a SessionStart — no PreToolUse, so ToolEventCount stays 0.
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-waiting"}`,
		"sess-waiting", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{})

	body := fetchSessionsHTML(t, srv, cookie, handler, "24h")
	if !strings.Contains(body, "Waiting for first tool call") {
		t.Errorf("expected waiting-state copy; body=%.400s", body)
	}
}

// TestSessions_RuntimeProtectedToolShowsCoverage — a runtime
// session that emitted tool calls reports the activity counters
// (tool count, subagent count where applicable) instead of the
// waiting-state copy.
func TestSessions_RuntimeProtectedToolShowsCoverage(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-cov"}`,
		"sess-cov", "local-codex", now.Add(-5*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SubagentStart","session_id":"sess-cov","agent_id":"sa-1","agent_type":"research"}`,
		"sess-cov", "local-codex", now.Add(-4*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-cov","agent_id":"sa-1","agent_type":"research","tool_name":"Read","tool_use_id":"u-cov"}`,
		"sess-cov", "local-codex", now.Add(-3*time.Minute), runtime.OutcomeRefs{Status: "delivered", CoverageMode: "protected", Confidence: 90})

	body := fetchSessionsHTML(t, srv, cookie, handler, "24h")
	if strings.Contains(body, "Waiting for first tool call") {
		t.Errorf("active-with-tools row should not show the waiting copy")
	}
	if !strings.Contains(body, "1 tool") {
		t.Errorf("expected '1 tool' activity summary; body=%.400s", body)
	}
}

// TestSessionDetail_RuntimeTreeAndTimeline — the runtime detail
// page renders the actor tree (root + subagent) and at least one
// timeline row referencing the seeded tool name.
func TestSessionDetail_RuntimeTreeAndTimeline(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-detail"}`,
		"sess-detail", "local-codex", now.Add(-5*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SubagentStart","session_id":"sess-detail","agent_id":"sa-d","agent_type":"investigator"}`,
		"sess-detail", "local-codex", now.Add(-4*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-detail","agent_id":"sa-d","agent_type":"investigator","tool_name":"Bash","tool_use_id":"u-detail"}`,
		"sess-detail", "local-codex", now.Add(-3*time.Minute), runtime.OutcomeRefs{Status: "delivered"})

	status, body := fetchSessionDetailHTML(t, srv, cookie, handler, "sess-detail")
	if status != http.StatusOK {
		t.Fatalf("detail status = %d, body=%s", status, body)
	}
	if !strings.Contains(body, "Actor tree") {
		t.Errorf("runtime detail missing actor tree section")
	}
	if !strings.Contains(body, "Timeline") {
		t.Errorf("runtime detail missing timeline section")
	}
	if !strings.Contains(body, "PreToolUse") {
		t.Errorf("runtime timeline missing seeded PreToolUse event")
	}
	if !strings.Contains(body, "subagent") {
		t.Errorf("runtime detail did not surface the subagent actor")
	}
	// AI sidebar must be hidden on runtime detail per spec.
	if strings.Contains(body, "Analyze with AI") || strings.Contains(body, "ai-analyze-btn") {
		t.Errorf("runtime detail leaked the audit AI button")
	}
}

// TestSessionDetail_RuntimeDoesNotLeakRawPayload — even when the
// hook envelope carries tool_input fields, the runtime detail
// HTML must only show hashes/tails, never the raw bytes.
func TestSessionDetail_RuntimeDoesNotLeakRawPayload(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-redact","tool_name":"Bash","tool_use_id":"u-redact","tool_input":{"command":"echo SUPER_SECRET_PAYLOAD_42"}}`,
		"sess-redact", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{Status: "delivered"})

	status, body := fetchSessionDetailHTML(t, srv, cookie, handler, "sess-redact")
	if status != http.StatusOK {
		t.Fatalf("detail status = %d", status)
	}
	if strings.Contains(body, "SUPER_SECRET_PAYLOAD_42") {
		t.Errorf("runtime detail HTML leaked raw tool input")
	}
}

// TestSessionExport_RuntimeJSON — the JSON export of a runtime
// session yields the runtime envelope shape (source, session,
// actors, events) and never carries raw tool input.
func TestSessionExport_RuntimeJSON(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-json","tool_name":"Read","tool_use_id":"u-json","tool_input":{"file":"SUPER_SECRET_FILENAME"}}`,
		"sess-json", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{Status: "delivered"})

	status, body, _ := fetchSessionExport(t, cookie, handler, "sess-json", "export")
	if status != http.StatusOK {
		t.Fatalf("export status = %d, body=%s", status, body)
	}
	if strings.Contains(body, "SUPER_SECRET_FILENAME") {
		t.Errorf("JSON export leaked raw payload field")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("export not valid JSON: %v", err)
	}
	if parsed["source"] != "runtime" {
		t.Errorf(`expected "source":"runtime", got %v`, parsed["source"])
	}
	if _, ok := parsed["events"]; !ok {
		t.Errorf("export missing events array")
	}
}

// TestSessionExport_RuntimeCSV — the CSV export uses the runtime
// column header set, not the legacy Step/Reasoning columns.
func TestSessionExport_RuntimeCSV(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-csv","tool_name":"Read","tool_use_id":"u-csv"}`,
		"sess-csv", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{Status: "delivered"})

	status, body, hdr := fetchSessionExport(t, cookie, handler, "sess-csv", "csv")
	if status != http.StatusOK {
		t.Fatalf("csv status = %d, body=%s", status, body)
	}
	if !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", hdr.Get("Content-Type"))
	}
	wantHeader := "timestamp,actor,kind,hook_event,lifecycle,stage,tool_name,tool_use_id,tool_input_hash,tool_output_hash,status,policy_decision,coverage_mode,confidence,latency_ms,audit_entry_id,activity_event_id"
	if !strings.Contains(body, wantHeader) {
		t.Errorf("runtime CSV header missing; got body=%.500s", body)
	}
	if strings.Contains(body, "Step,Timestamp,Tool,Verdict") {
		t.Errorf("runtime CSV emitted the legacy audit header instead of the runtime shape")
	}
}

// fetchCoverageDrawer hits the cell drawer endpoint for one
// (principal, surface) pair and returns the rendered HTML.
func fetchCoverageDrawer(t *testing.T, cookie *http.Cookie, handler http.Handler, principalID, surface string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/dashboard/api/coverage/cell?principal_id="+principalID+"&surface="+surface, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	return w.Code, string(body)
}

// TestCoverageHooksDrawer_UsesRuntimeRealEvents — when the
// principal has runtime hook events, the drawer renders the
// runtime block ("Runtime hook events" heading) with the seeded
// hook event name.
func TestCoverageHooksDrawer_UsesRuntimeRealEvents(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-drawer","tool_name":"Read","tool_use_id":"u-drawer"}`,
		"sess-drawer", "local-codex", now.Add(-1*time.Minute), runtime.OutcomeRefs{Status: "delivered", CoverageMode: "protected"})

	status, body := fetchCoverageDrawer(t, cookie, handler, "local-codex", "hooks")
	if status != http.StatusOK {
		t.Fatalf("drawer status = %d, body=%.300s", status, body)
	}
	if !strings.Contains(body, "Runtime hook events") {
		t.Errorf("drawer did not render the runtime branch heading; body=%.500s", body)
	}
	if !strings.Contains(body, "PreToolUse") {
		t.Errorf("runtime drawer missing seeded hook event")
	}
}

// TestCoverageHooksDrawer_HeartbeatOnlyDiagnostic — when the only
// runtime evidence for the principal is a heartbeat session, the
// drawer renders the diagnostic banner and does not show the
// "Runtime hook events" list nor fall back to the activity store.
func TestCoverageHooksDrawer_HeartbeatOnlyDiagnostic(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026-04-30-x"}`,
		"heartbeat-2026-04-30-x", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{})

	status, body := fetchCoverageDrawer(t, cookie, handler, "local-codex", "hooks")
	if status != http.StatusOK {
		t.Fatalf("drawer status = %d, body=%.300s", status, body)
	}
	if !strings.Contains(body, "Heartbeat reached the gateway") {
		t.Errorf("expected heartbeat diagnostic copy; body=%.500s", body)
	}
	if strings.Contains(body, "Runtime hook events") {
		t.Errorf("drawer rendered the runtime events block on a heartbeat-only state")
	}
	if strings.Contains(body, "Last 20 activity events") {
		t.Errorf("drawer fell back to legacy activity events on a heartbeat-only state")
	}
}

// TestCoverageDrawer_MCPAndEgressUnchanged — the runtime branch
// only fires for surface=hooks. mcp_http and http_egress_proxy
// continue to render the legacy activity-store block (the
// "Last N activity events" heading) regardless of runtime
// evidence.
func TestCoverageDrawer_MCPAndEgressUnchanged(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	// Seed runtime evidence the runtime branch would otherwise pick up.
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-other","tool_name":"Read","tool_use_id":"u-other"}`,
		"sess-other", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{Status: "delivered"})

	for _, surface := range []string{"mcp_http", "http_egress_proxy"} {
		status, body := fetchCoverageDrawer(t, cookie, handler, "local-codex", surface)
		if status != http.StatusOK {
			t.Fatalf("drawer status for %s = %d", surface, status)
		}
		if strings.Contains(body, "Runtime hook events") {
			t.Errorf("surface %s drawer leaked the runtime block", surface)
		}
		if strings.Contains(body, "Heartbeat reached the gateway") {
			t.Errorf("surface %s drawer leaked the heartbeat diagnostic", surface)
		}
		if !strings.Contains(body, "Last 20 activity events") {
			t.Errorf("surface %s drawer missing the legacy activity heading; body=%.500s", surface, body)
		}
	}
}
