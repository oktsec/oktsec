package proxy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity/resolve"
)

// recordingActivityWriter is a test double for activityWriter that
// captures every Insert call. The mu makes it safe to read from the
// test goroutine while the proxy's emit goroutine writes.
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

// waitForProxyActivity polls the recorder until it has at least n
// events or the deadline elapses. The proxy emits activity in a
// goroutine so a blocking wait is the fairest way to assert against
// it without sleep races.
func waitForProxyActivity(t *testing.T, r *recordingActivityWriter, n int) []activity.Event {
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

// 1. Authenticated egress (proxy_token) emits a Protected activity
// event with confidence 100 and the audit row id correlated through
// AuditEntryID.
func TestForwardProxyActivity_AuthenticatedIsProtected(t *testing.T) {
	fp, _ := newTestForwardProxy(t, &config.ForwardProxyConfig{Enabled: true})
	rec := &recordingActivityWriter{}
	fp.SetActivityStore(rec)

	auth := proxyAuth{
		PrincipalID:   "local-codex",
		AuthMethod:    string(resolve.AuthMethodProxyToken),
		TrustLevel:    string(resolve.TrustAuthenticated),
		ReportedActor: "",
	}
	fp.logProxyEntry("127.0.0.1", "GET", "api.example.com:443", "forwarded", "proxy_allowed", "", "sess-1", 1024, time.Now(), auth)

	events := waitForProxyActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal = %q; want local-codex", ev.PrincipalID)
	}
	if ev.AuthMethod != string(resolve.AuthMethodProxyToken) {
		t.Errorf("auth_method = %q; want proxy_token", ev.AuthMethod)
	}
	if ev.CoverageMode != activity.CoverageProtected {
		t.Errorf("coverage = %q; want protected", ev.CoverageMode)
	}
	if ev.Confidence != 100 {
		t.Errorf("confidence = %d; want 100", ev.Confidence)
	}
	if ev.Surface != activity.SurfaceHTTPEgressProxy || ev.EventType != activity.EventEgressRequest {
		t.Errorf("surface/event = %q/%q; want http_egress_proxy/egress.request", ev.Surface, ev.EventType)
	}
	if ev.AuditEntryID == "" {
		t.Error("audit_entry_id should be populated for correlation")
	}
	if ev.ResourceLabel != "api.example.com:443" {
		t.Errorf("resource_label = %q; want api.example.com:443", ev.ResourceLabel)
	}
}

// 2. Reported actor (e.g., spoofed agent name from a header) is
// preserved as ReportedActor on the activity event but never replaces
// the resolver-established principal.
func TestForwardProxyActivity_ReportedActorDoesNotReplacePrincipal(t *testing.T) {
	fp, _ := newTestForwardProxy(t, &config.ForwardProxyConfig{Enabled: true})
	rec := &recordingActivityWriter{}
	fp.SetActivityStore(rec)

	auth := proxyAuth{
		PrincipalID:   "local-codex",
		AuthMethod:    string(resolve.AuthMethodProxyToken),
		TrustLevel:    string(resolve.TrustAuthenticated),
		ReportedActor: "admin",
	}
	fp.logProxyEntry("127.0.0.1", "GET", "api.example.com:443", "forwarded", "proxy_allowed", "", "sess-1", 0, time.Now(), auth)

	events := waitForProxyActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal = %q; want local-codex (spoof must not replace)", ev.PrincipalID)
	}
	if ev.ReportedActor != "admin" {
		t.Errorf("reported_actor = %q; want admin", ev.ReportedActor)
	}
}

// 3. Unauthenticated egress (empty auth method) still emits an
// activity event so the dashboard sees the surface as Observed rather
// than Blind. Empty principal id resolves to "unknown" so the row
// validates against the activity store invariant.
func TestForwardProxyActivity_UnauthenticatedIsObserved(t *testing.T) {
	fp, _ := newTestForwardProxy(t, &config.ForwardProxyConfig{Enabled: true})
	rec := &recordingActivityWriter{}
	fp.SetActivityStore(rec)

	auth := proxyAuth{} // no principal, no auth method
	fp.logProxyEntry("127.0.0.1", "GET", "api.example.com:443", "forwarded", "proxy_allowed", "", "sess-1", 0, time.Now(), auth)

	events := waitForProxyActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "unknown" {
		t.Errorf("principal = %q; want unknown (empty principal must collapse to unknown)", ev.PrincipalID)
	}
	if ev.CoverageMode != activity.CoverageObserved {
		t.Errorf("coverage = %q; want observed", ev.CoverageMode)
	}
	if ev.Confidence != 0 {
		t.Errorf("confidence = %d; want 0", ev.Confidence)
	}
}

// 4. When the proxy's activity field is nil (audit store without DB
// or pre-PR3 setups), logProxyEntry still writes audit and returns.
// Activity emission is best-effort; it must never gate the request.
func TestForwardProxyActivity_NilStoreDoesNotBreakRequest(t *testing.T) {
	fp, store := newTestForwardProxy(t, &config.ForwardProxyConfig{Enabled: true})
	fp.SetActivityStore(nil) // explicitly disable

	auth := proxyAuth{
		PrincipalID: "local-codex",
		AuthMethod:  string(resolve.AuthMethodProxyToken),
		TrustLevel:  string(resolve.TrustAuthenticated),
	}
	fp.logProxyEntry("127.0.0.1", "GET", "api.example.com:443", "forwarded", "proxy_allowed", "", "sess-1", 0, time.Now(), auth)

	// Audit row should still be present.
	store.Flush()
	if _, err := store.Query(audit.QueryOpts{Agent: "127.0.0.1", Limit: 1}); err != nil {
		t.Errorf("audit query: %v", err)
	}
}

// 5. An Insert error from the activity store is logged but does NOT
// affect the audit row. Activity is a secondary write; failures must
// not be visible to the client.
func TestForwardProxyActivity_InsertErrorDoesNotAffectAudit(t *testing.T) {
	fp, store := newTestForwardProxy(t, &config.ForwardProxyConfig{Enabled: true})
	rec := &recordingActivityWriter{err: errors.New("simulated db down")}
	fp.SetActivityStore(rec)

	auth := proxyAuth{
		PrincipalID: "local-codex",
		AuthMethod:  string(resolve.AuthMethodProxyToken),
		TrustLevel:  string(resolve.TrustAuthenticated),
	}
	fp.logProxyEntry("127.0.0.1", "GET", "api.example.com:443", "forwarded", "proxy_allowed", "", "sess-1", 0, time.Now(), auth)

	// Audit row is the compliance trail and must still land.
	store.Flush()
	entries, err := store.Query(audit.QueryOpts{Agent: "127.0.0.1", Limit: 1})
	if err != nil || len(entries) == 0 {
		t.Errorf("audit row missing after activity failure (entries=%d, err=%v)", len(entries), err)
	}
	// Give the goroutine time to attempt and fail; recorder should
	// still hold zero events because Insert returned an error.
	time.Sleep(50 * time.Millisecond)
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("recorder should hold zero events on Insert error; got %d", len(got))
	}
}

// 6. Blocked egress (e.g., domain blocked) emits an activity event
// with status=blocked. The contract is "every audit row has a paired
// activity event", and this test guards the blocked early-return
// paths from silently bypassing dual-write.
func TestForwardProxyActivity_BlockedRequestStillEmitsActivity(t *testing.T) {
	fp, _ := newTestForwardProxy(t, &config.ForwardProxyConfig{Enabled: true})
	rec := &recordingActivityWriter{}
	fp.SetActivityStore(rec)

	auth := proxyAuth{
		PrincipalID: "local-codex",
		AuthMethod:  string(resolve.AuthMethodProxyToken),
		TrustLevel:  string(resolve.TrustAuthenticated),
	}
	fp.logProxyEntry("127.0.0.1", "CONNECT", "evil.example.com:443", audit.StatusBlocked, "proxy_blocked_domain", "", "sess-1", 0, time.Now(), auth)

	events := waitForProxyActivity(t, rec, 1)
	ev := events[0]
	if ev.Status != audit.StatusBlocked {
		t.Errorf("status = %q; want %q (blocked path must surface in activity)", ev.Status, audit.StatusBlocked)
	}
	if ev.PolicyDecision == "" {
		t.Errorf("policy_decision should explain why request was blocked; got empty")
	}
	if ev.Surface != activity.SurfaceHTTPEgressProxy {
		t.Errorf("surface = %q; want http_egress_proxy", ev.Surface)
	}
}
