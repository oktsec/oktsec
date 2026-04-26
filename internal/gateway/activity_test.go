package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity/resolve"
)

// recordingActivityWriter is a test double for activityWriter that
// captures every Insert call. The mu makes it safe to read from the
// test goroutine while the gateway's emit goroutine writes.
type recordingActivityWriter struct {
	mu     sync.Mutex
	events []activity.Event
	err    error // when set, every Insert returns this error
}

func (r *recordingActivityWriter) Insert(_ context.Context, e activity.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recordingActivityWriter) snapshot() []activity.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]activity.Event, len(r.events))
	copy(out, r.events)
	return out
}

// waitForActivity polls the recorder until it has at least n events or
// the deadline elapses. The gateway emits activity in a goroutine so a
// blocking wait is the fairest way to assert against it without sleep
// races.
func waitForActivity(t *testing.T, r *recordingActivityWriter, n int) []activity.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := r.snapshot()
		if len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("activity recorder: wanted %d events, got %d", n, len(r.snapshot()))
	return nil
}

// 1. Bearer-authenticated tool call writes a Protected activity event
// with bearer_token / authenticated identity. Confidence is 100. The
// audit row id is preserved as AuditEntryID for correlation.
func TestGatewayActivity_BearerToolCallProtected(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{}
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	rec := &recordingActivityWriter{}
	gw.SetActivityStore(rec)

	ctx := ctxWithIdentity("local-codex",
		string(resolve.AuthMethodBearerToken),
		string(resolve.TrustAuthenticated), "")
	handler := gw.makeHandler(gw.toolMap["echo"])
	if _, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"})); err != nil {
		t.Fatalf("handler: %v", err)
	}

	events := waitForActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal = %q; want local-codex", ev.PrincipalID)
	}
	if ev.AuthMethod != string(resolve.AuthMethodBearerToken) {
		t.Errorf("auth_method = %q; want bearer_token", ev.AuthMethod)
	}
	if ev.CoverageMode != activity.CoverageProtected {
		t.Errorf("coverage = %q; want protected", ev.CoverageMode)
	}
	if ev.Confidence != 100 {
		t.Errorf("confidence = %d; want 100", ev.Confidence)
	}
	if ev.Surface != activity.SurfaceMCPHTTP || ev.EventType != activity.EventMCPToolCall {
		t.Errorf("surface/event = %q/%q; want mcp_http/mcp.tool_call", ev.Surface, ev.EventType)
	}
	if ev.AuditEntryID == "" {
		t.Error("audit_entry_id should be populated for correlation")
	}
}

// 2. Reported actor (e.g. spoofed X-Oktsec-Agent or _oktsec_agent
// payload param) is preserved as ReportedActor on the activity event
// but never replaces the bearer-token principal.
func TestGatewayActivity_ReportedActorDoesNotReplacePrincipal(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{}
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	rec := &recordingActivityWriter{}
	gw.SetActivityStore(rec)

	ctx := ctxWithIdentity("local-codex",
		string(resolve.AuthMethodBearerToken),
		string(resolve.TrustAuthenticated),
		"admin") // spoofed reported actor
	handler := gw.makeHandler(gw.toolMap["echo"])
	if _, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"})); err != nil {
		t.Fatalf("handler: %v", err)
	}

	events := waitForActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal = %q; want local-codex (spoof must not replace)", ev.PrincipalID)
	}
	if ev.ReportedActor != "admin" {
		t.Errorf("reported_actor = %q; want admin", ev.ReportedActor)
	}
}

// 3. Trusted_loopback identity (legacy local header path) writes an
// Observed activity event, not Protected. Confidence is 80. This is
// the contract that prevents the dashboard from claiming protection
// for the loopback header.
func TestGatewayActivity_TrustedLoopbackIsObserved(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["claude-code"] = config.Agent{}
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	rec := &recordingActivityWriter{}
	gw.SetActivityStore(rec)

	ctx := ctxWithIdentity("claude-code",
		string(resolve.AuthMethodTrustedLoopback),
		string(resolve.TrustLocal), "")
	handler := gw.makeHandler(gw.toolMap["echo"])
	if _, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"})); err != nil {
		t.Fatalf("handler: %v", err)
	}

	events := waitForActivity(t, rec, 1)
	ev := events[0]
	if ev.CoverageMode != activity.CoverageObserved {
		t.Errorf("coverage = %q; want observed (loopback header is not protected)", ev.CoverageMode)
	}
	if ev.Confidence != 80 {
		t.Errorf("confidence = %d; want 80", ev.Confidence)
	}
	if ev.AuthMethod != string(resolve.AuthMethodTrustedLoopback) {
		t.Errorf("auth_method = %q; want trusted_loopback", ev.AuthMethod)
	}
}

// 4. When the gateway's activity field is nil (no audit DB handle, or
// pre-PR2 setups), the handler still writes audit and returns success.
// Activity emission is best-effort; it must never gate the request.
func TestGatewayActivity_NilStoreDoesNotBreakHandler(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{}
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	gw.SetActivityStore(nil) // explicitly disable

	ctx := ctxWithIdentity("local-codex",
		string(resolve.AuthMethodBearerToken),
		string(resolve.TrustAuthenticated), "")
	handler := gw.makeHandler(gw.toolMap["echo"])
	res, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler returned MCP error: %+v", res)
	}
	// Audit row should still be present.
	gw.audit.Flush()
	if _, err := gw.audit.Query(audit.QueryOpts{Agent: "local-codex", Limit: 1}); err != nil {
		t.Errorf("audit query: %v", err)
	}
}

// 5. An Insert error from the activity store is logged but does NOT
// affect the handler's success or the audit row. Activity is a
// secondary write; failures must not be visible to the client.
func TestGatewayActivity_InsertErrorDoesNotAffectRequest(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{}
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	rec := &recordingActivityWriter{err: errors.New("simulated db down")}
	gw.SetActivityStore(rec)

	ctx := ctxWithIdentity("local-codex",
		string(resolve.AuthMethodBearerToken),
		string(resolve.TrustAuthenticated), "")
	handler := gw.makeHandler(gw.toolMap["echo"])
	res, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"}))
	if err != nil {
		t.Fatalf("handler must succeed even when activity insert fails; got %v", err)
	}
	if res.IsError {
		t.Errorf("handler returned MCP error on activity failure: %+v", res)
	}
	// Audit row is the compliance trail and must still land.
	gw.audit.Flush()
	entries, err := gw.audit.Query(audit.QueryOpts{Agent: "local-codex", Limit: 1})
	if err != nil || len(entries) == 0 {
		t.Errorf("audit row missing after activity failure (entries=%d, err=%v)", len(entries), err)
	}
	// Give the goroutine time to attempt and fail; recorder should still
	// have zero events because Insert returned an error.
	time.Sleep(50 * time.Millisecond)
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("recorder should hold zero events on Insert error; got %d", len(got))
	}
}

// 6. Early-return blocked paths (rate limit, allowlist, etc.) emit
// activity events too. The contract is "every audit row has a paired
// activity event", and this test guards the most important class —
// security-blocked requests — from silently bypassing dual-write.
func TestGatewayActivity_BlockedRequestStillEmitsActivity(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{
		AllowedTools: []string{"only-this-tool"}, // echo is NOT in the allowlist
	}
	// Map test-agent so the allowlist check matches our principal.
	cfg.Agents["local-codex"] = config.Agent{
		AllowedTools: []string{"only-this-tool"},
	}
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	rec := &recordingActivityWriter{}
	gw.SetActivityStore(rec)

	ctx := ctxWithIdentity("local-codex",
		string(resolve.AuthMethodBearerToken),
		string(resolve.TrustAuthenticated), "")
	handler := gw.makeHandler(gw.toolMap["echo"])
	// Allowlist mismatch produces an MCP error result with status=blocked.
	if _, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"})); err != nil {
		t.Fatalf("handler: %v", err)
	}

	events := waitForActivity(t, rec, 1)
	ev := events[0]
	if ev.Status != audit.StatusBlocked {
		t.Errorf("status = %q; want %q (blocked path must surface in activity)", ev.Status, audit.StatusBlocked)
	}
	if ev.PolicyDecision == "" {
		t.Errorf("policy_decision should explain why request was blocked; got empty")
	}
	if ev.Surface != activity.SurfaceMCPHTTP {
		t.Errorf("surface = %q; want mcp_http", ev.Surface)
	}
}
