package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/runtime"
)

// runtime_session_analysis_test.go covers the Phase 4C runtime
// AI flow. The fixture wires an OpenAI-compatible httptest
// server so we can capture the prompt body and assert the
// runtime path emits the expected envelope shape — without
// reaching out to a real LLM provider.

// fakeLLM is a minimal OpenAI-compatible /chat/completions
// stub that records the most recent request body so a test can
// inspect the prompt the runtime analyser built.
type fakeLLM struct {
	server *httptest.Server
	mu     sync.Mutex
	last   []byte
	reply  string
}

func newFakeLLM(t *testing.T, reply string) *fakeLLM {
	t.Helper()
	f := &fakeLLM{reply: reply}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.last = body
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": f.reply}},
			},
		})
	}))
	t.Cleanup(f.server.Close)
	return f
}

// promptText extracts the user-message content from the most
// recent captured request. Tests assert against this so the
// substring matches focus on the prompt body, not the JSON
// envelope.
func (f *fakeLLM) promptText(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		t.Fatal("fake LLM did not receive a request")
	}
	var parsed struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(f.last, &parsed); err != nil {
		t.Fatalf("decode prompt JSON: %v; body=%s", err, string(f.last))
	}
	if len(parsed.Messages) == 0 {
		t.Fatal("fake LLM request had no messages")
	}
	return parsed.Messages[0].Content
}

// newRuntimeAnalysisServer wires a Server with both the runtime
// store AND an LLM config pointing at the fake LLM. cfgPath is
// set so any config save in the request path can write.
func newRuntimeAnalysisServer(t *testing.T, fake *fakeLLM) (*Server, *runtime.Store, *audit.Store) {
	t.Helper()
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	srv.cfg.LLM = config.LLMConfig{
		Enabled:  true,
		Provider: "openai",
		Model:    "test-model",
		APIKey:   "test-key",
		BaseURL:  fake.server.URL,
	}
	return srv, rs, auditStore
}

// seedRealActivity drops a SessionStart + SubagentStart +
// PreToolUse with hashed input + a delivered status, so the
// session has analysable real activity.
func seedRealActivity(t *testing.T, rs *runtime.Store, sessionID string, ts time.Time, secret string) {
	t.Helper()
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"`+sessionID+`"}`,
		sessionID, "local-codex", ts.Add(-5*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SubagentStart","session_id":"`+sessionID+`","agent_id":"sa-1","agent_type":"research"}`,
		sessionID, "local-codex", ts.Add(-4*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"`+sessionID+`","agent_id":"sa-1","agent_type":"research","tool_name":"Read","tool_use_id":"u-real","tool_input":{"file":"`+secret+`"}}`,
		sessionID, "local-codex", ts.Add(-3*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
}

// postAnalyze fires the analyse endpoint and returns the
// response.
func postAnalyze(t *testing.T, handler http.Handler, cookie *http.Cookie, sessionID string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/dashboard/api/sessions/"+sessionID+"/analyze", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// TestSessionDetail_RuntimeShowsAnalyzeButtonForRealActivity —
// when LLM is enabled and the runtime session has real (non-
// heartbeat) events, the runtime detail page renders the
// runtime AI button.
func TestSessionDetail_RuntimeShowsAnalyzeButtonForRealActivity(t *testing.T) {
	fake := newFakeLLM(t, "ok")
	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRealActivity(t, rs, "sess-ai-real", now, "INNOCUOUS")

	status, body := fetchSessionDetailHTML(t, srv, cookie, handler, "sess-ai-real")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(body, `id="rt-ai-analyze-btn"`) {
		t.Errorf("runtime detail did not render the runtime AI button for real activity")
	}
}

// TestSessionDetail_RuntimeHidesAnalyzeButtonForHeartbeatOnly —
// heartbeat-only sessions never get an AI button. The
// diagnostic banner stays.
func TestSessionDetail_RuntimeHidesAnalyzeButtonForHeartbeatOnly(t *testing.T) {
	fake := newFakeLLM(t, "ok")
	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026-04-30-ai"}`,
		"heartbeat-2026-04-30-ai", "local-codex", now.Add(-1*time.Minute), runtime.OutcomeRefs{})

	status, body := fetchSessionDetailHTML(t, srv, cookie, handler, "heartbeat-2026-04-30-ai")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if strings.Contains(body, `id="rt-ai-analyze-btn"`) {
		t.Errorf("runtime detail rendered the AI button on a heartbeat-only session")
	}
	if !strings.Contains(body, "diagnostic") {
		t.Errorf("runtime detail missing the diagnostic banner / wording for heartbeat-only")
	}
}

// TestSessionAnalyze_RuntimeSessionDoesNotRequireAuditTrace —
// the runtime path must work even when audit.BuildSessionTrace
// would return nothing for the same id. The Phase 3C runtime
// path stopped writing audit rows for runtime-only sessions, so
// the analyser must not require them.
func TestSessionAnalyze_RuntimeSessionDoesNotRequireAuditTrace(t *testing.T) {
	fake := newFakeLLM(t, "**Risk Level:** CLEAN.\nFake reply.")
	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRealActivity(t, rs, "sess-ai-no-audit", now, "INNOCUOUS")

	status, body := postAnalyze(t, handler, cookie, "sess-ai-no-audit")
	if status != http.StatusOK {
		t.Fatalf("analyze status = %d, body=%s", status, body)
	}
	if !strings.Contains(body, "Fake reply") {
		t.Errorf("response did not pass the LLM reply through; got %q", body)
	}
}

// TestSessionAnalyze_RuntimePromptUsesHashesNotRawPayload —
// the runtime envelope must redact tool_input / tool_output to
// hashes only. Seed a session where tool_input carries a
// distinctive secret string and assert the prompt does not
// contain it. The prompt MUST contain the runtime "source"
// marker and the seeded hook event name so the test catches a
// regression that drops the runtime path entirely.
func TestSessionAnalyze_RuntimePromptUsesHashesNotRawPayload(t *testing.T) {
	fake := newFakeLLM(t, "ok")
	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	const secret = "SECRET_PAYLOAD_DO_NOT_LEAK_42"
	seedRealActivity(t, rs, "sess-ai-redact", now, secret)

	status, body := postAnalyze(t, handler, cookie, "sess-ai-redact")
	if status != http.StatusOK {
		t.Fatalf("analyze status = %d, body=%s", status, body)
	}
	prompt := fake.promptText(t)
	if strings.Contains(prompt, secret) {
		t.Errorf("prompt leaked raw tool_input value")
	}
	if !strings.Contains(prompt, "source: runtime") {
		t.Errorf("prompt missing runtime source marker")
	}
	if !strings.Contains(prompt, "PreToolUse") {
		t.Errorf("prompt missing seeded hook event name")
	}
	if !strings.Contains(prompt, "sha256:") {
		t.Errorf("prompt missing hash marker for tool input")
	}
}

// TestSessionAnalyze_RuntimeDoesNotDisplayLegacyAuditAnalysis —
// when the runtime path saves an analysis under runtime:<id>,
// a legacy audit analysis previously stored under the bare id
// must NOT show up on the runtime detail page. Save both
// directly into the audit store and assert the runtime detail
// renders only the runtime version.
func TestSessionAnalyze_RuntimeDoesNotDisplayLegacyAuditAnalysis(t *testing.T) {
	fake := newFakeLLM(t, "ok")
	srv, rs, auditStore := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRealActivity(t, rs, "sess-ai-isolation", now, "INNOCUOUS")

	const auditMarker = "AUDIT_ANALYSIS_SHOULD_NOT_RENDER"
	const runtimeMarker = "RUNTIME_ANALYSIS_VISIBLE"
	if err := auditStore.SaveSessionAnalysis("sess-ai-isolation", auditMarker, "test/audit"); err != nil {
		t.Fatal(err)
	}
	if err := auditStore.SaveSessionAnalysis(runtimeSessionAnalysisKey("sess-ai-isolation"), runtimeMarker, "test/runtime"); err != nil {
		t.Fatal(err)
	}

	status, body := fetchSessionDetailHTML(t, srv, cookie, handler, "sess-ai-isolation")
	if status != http.StatusOK {
		t.Fatalf("detail status = %d", status)
	}
	if strings.Contains(body, auditMarker) {
		t.Errorf("runtime detail displayed legacy audit analysis text")
	}
	if !strings.Contains(body, runtimeMarker) {
		t.Errorf("runtime detail missing the runtime-keyed analysis text")
	}
}

// TestSessionAnalyze_RuntimeSavedAnalysisRendersInDetail — full
// round-trip: POST analyse, then GET detail and assert the
// rendered HTML carries the LLM reply text.
func TestSessionAnalyze_RuntimeSavedAnalysisRendersInDetail(t *testing.T) {
	const llmText = "**Risk Level:** LOW. Fake assessment for the runtime path."
	fake := newFakeLLM(t, llmText)
	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRealActivity(t, rs, "sess-ai-roundtrip", now, "INNOCUOUS")

	status, _ := postAnalyze(t, handler, cookie, "sess-ai-roundtrip")
	if status != http.StatusOK {
		t.Fatalf("analyze status = %d", status)
	}

	status, body := fetchSessionDetailHTML(t, srv, cookie, handler, "sess-ai-roundtrip")
	if status != http.StatusOK {
		t.Fatalf("detail status = %d", status)
	}
	if !strings.Contains(body, "Fake assessment for the runtime path.") {
		t.Errorf("detail did not render the saved runtime analysis text")
	}
	if !strings.Contains(body, `id="rt-ai-panel"`) {
		t.Errorf("detail missing the runtime AI panel container")
	}
}

// TestSessionAnalyze_HeartbeatOnlyRuntimeSessionRejected — a
// heartbeat-only session must not reach the LLM. The handler
// returns 400 with a clear reason, and the fake LLM must NOT
// receive any request.
func TestSessionAnalyze_HeartbeatOnlyRuntimeSessionRejected(t *testing.T) {
	fake := newFakeLLM(t, "ok")
	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026-04-30-reject"}`,
		"heartbeat-2026-04-30-reject", "local-codex", now.Add(-1*time.Minute), runtime.OutcomeRefs{})

	status, body := postAnalyze(t, handler, cookie, "heartbeat-2026-04-30-reject")
	if status != http.StatusBadRequest {
		t.Fatalf("analyze status = %d, want 400; body=%s", status, body)
	}
	if !strings.Contains(body, "heartbeat") {
		t.Errorf("rejection reason should mention heartbeat; got %q", body)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.last != nil {
		t.Errorf("fake LLM received a request despite heartbeat-only rejection")
	}
}

// TestSessionAnalyze_AuditFallbackStillWorksForLegacySession —
// when no runtime row exists for the id, the analyser falls
// back to the audit BuildSessionTrace path and saves under the
// bare sessionID. Pre-Phase 4C behaviour preserved.
func TestSessionAnalyze_AuditFallbackStillWorksForLegacySession(t *testing.T) {
	fake := newFakeLLM(t, "**Risk Level:** CLEAN. Audit path reply.")
	srv, _, auditStore := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	// Audit-only session: write a row directly. No runtime
	// row for this id.
	auditStore.Log(audit.Entry{
		ID:             "audit-only-event",
		Timestamp:      now.Add(-5 * time.Minute).Format(time.RFC3339),
		FromAgent:      "human-user",
		ToAgent:        "echo",
		Status:         "delivered",
		PolicyDecision: "allow",
		SessionID:      "audit-only-session",
		ContentHash:    "h",
	})
	auditStore.Flush()

	status, body := postAnalyze(t, handler, cookie, "audit-only-session")
	if status != http.StatusOK {
		t.Fatalf("analyze status = %d, body=%s", status, body)
	}
	if !strings.Contains(body, "Audit path reply.") {
		t.Errorf("audit fallback did not pass through LLM reply; got %q", body)
	}
	// And the saved analysis must live under the bare id, not
	// runtime:<id>.
	if got := auditStore.QuerySessionAnalysis("audit-only-session"); got == nil {
		t.Errorf("audit fallback did not persist analysis under bare sessionID")
	}
	if got := auditStore.QuerySessionAnalysis(runtimeSessionAnalysisKey("audit-only-session")); got != nil {
		t.Errorf("audit fallback wrote into the runtime: namespace")
	}
}

// TestSessionAnalyze_RuntimeQueryErrorReturns503 — review #172
// P2 #1: when buildRuntimeSessionAnalysisEnvelope sees a runtime
// store error (here: underlying DB closed mid-flight), the
// handler must surface 503 and NOT silently fall through to the
// audit path. The fake LLM must also stay untouched, since the
// runtime probe never succeeded.
func TestSessionAnalyze_RuntimeQueryErrorReturns503(t *testing.T) {
	fake := newFakeLLM(t, "ok")
	srv, rs, auditStore := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRealActivity(t, rs, "sess-runtime-503", now, "INNOCUOUS")

	// Force the runtime QuerySession to fail by closing the
	// shared *sql.DB. audit.Store.Close is idempotent so the
	// t.Cleanup re-close is safe.
	if err := auditStore.Close(); err != nil {
		t.Fatalf("close audit store: %v", err)
	}

	status, body := postAnalyze(t, handler, cookie, "sess-runtime-503")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("analyze status = %d, want 503; body=%s", status, body)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.last != nil {
		t.Errorf("fake LLM was called despite runtime query error")
	}
}

// TestSessionAnalyze_RuntimeAIErrorPanelEscapesUpstreamXSS —
// review #172 P2 #2: a hostile or misconfigured upstream LLM
// can return arbitrary text in its error message. The handler
// propagates that text to the client; the client-side error
// renderer in tmpl_session.go MUST inject it into the DOM via
// textContent, never via innerHTML +=. We assert both halves of
// the contract: the API surfaces the error body so the JS catch
// receives it, and the rendered template carries the canonical
// textContent assignment with no innerHTML += anywhere in the
// runtime AI fallback path.
func TestSessionAnalyze_RuntimeAIErrorPanelEscapesUpstreamXSS(t *testing.T) {
	xssBody := `{"error":{"message":"<img src=x onerror=alert(1)>"}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(xssBody))
	}))
	t.Cleanup(server.Close)
	fake := &fakeLLM{server: server}

	srv, rs, _ := newRuntimeAnalysisServer(t, fake)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRealActivity(t, rs, "sess-xss-1", now, "INNOCUOUS")

	status, body := postAnalyze(t, handler, cookie, "sess-xss-1")
	if status == http.StatusOK {
		t.Fatalf("expected non-200 from analyze when LLM errors, got 200; body=%s", body)
	}

	detailStatus, detailBody := fetchSessionDetailHTML(t, srv, cookie, handler, "sess-xss-1")
	if detailStatus != http.StatusOK {
		t.Fatalf("detail status = %d", detailStatus)
	}
	if !strings.Contains(detailBody, "txt.textContent = 'Analysis failed: ' + e.message") {
		t.Errorf("rt error path must build text via textContent; missing canonical line")
	}
	if strings.Contains(detailBody, "innerHTML += ") || strings.Contains(detailBody, "innerHTML+=") {
		t.Errorf("rt error path must NOT use innerHTML += (XSS regression risk)")
	}
}
