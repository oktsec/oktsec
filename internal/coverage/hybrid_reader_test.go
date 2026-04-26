package coverage

import (
	"errors"
	"testing"
)

// stubReader is the minimum AuditReader the hybrid reader tests need.
// One canned timestamp string keyed by principal+surface, plus an
// optional error so we can exercise the activity-failure fallback path.
type stubReader struct {
	stamps map[string]string
	err    error
}

func (s stubReader) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.stamps[principalID+"|"+surface], nil
}

// 1. When activity carries the later timestamp, the hybrid reader
// returns it. Common path once activity has been wired up.
func TestHybridLastSeenReader_ActivityWinsWhenNewer(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-26T10:00:00Z"}},
		Audit:    stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-25T08:00:00Z"}},
	}
	got, err := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if err != nil {
		t.Fatalf("err = %v; want nil", err)
	}
	if got != "2026-04-26T10:00:00Z" {
		t.Errorf("got = %q; want activity timestamp 2026-04-26T10:00:00Z", got)
	}
}

// 2. AUDIT can carry a NEWER row when activity missed an insert (the
// dual-write goroutine raced with a query, the activity DB hiccupped,
// etc.). The hybrid reader must surface the audit value in that case
// so the dashboard does not show stale coverage. Regression guard for
// the original "activity wins as soon as it has any row" bug.
func TestHybridLastSeenReader_AuditWinsWhenNewer(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-25T08:00:00Z"}},
		Audit:    stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-26T10:00:00Z"}},
	}
	got, _ := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if got != "2026-04-26T10:00:00Z" {
		t.Errorf("got = %q; want audit timestamp 2026-04-26T10:00:00Z (audit was newer)", got)
	}
}

// 3. When activity has no row for the pair, the audit fallback fills
// in the LastSeen so historical events from before activity was wired
// up still appear in the matrix.
func TestHybridLastSeenReader_FallsBackToAudit(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{stamps: map[string]string{}}, // empty
		Audit:    stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-25T08:00:00Z"}},
	}
	got, _ := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if got != "2026-04-25T08:00:00Z" {
		t.Errorf("got = %q; want audit fallback 2026-04-25T08:00:00Z", got)
	}
}

// 4. An activity error is treated the same as an empty row: the audit
// fallback still gets a chance. Activity is best-effort; an outage
// there must not blank columns the operator already trusts.
func TestHybridLastSeenReader_ActivityErrorFallsBack(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{err: errors.New("simulated activity outage")},
		Audit:    stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-25T08:00:00Z"}},
	}
	got, err := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if err != nil {
		t.Fatalf("err = %v; want nil (activity error swallowed)", err)
	}
	if got != "2026-04-25T08:00:00Z" {
		t.Errorf("got = %q; want audit fallback after activity error", got)
	}
}

// 5. With both readers nil the hybrid returns empty cleanly. This is
// the degenerate case Compute already handles by skipping the
// LastSeen assignment, but the contract here keeps it from panicking.
func TestHybridLastSeenReader_BothNil(t *testing.T) {
	h := HybridLastSeenReader{}
	got, err := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if err != nil {
		t.Errorf("err = %v; want nil", err)
	}
	if got != "" {
		t.Errorf("got = %q; want empty", got)
	}
}

// 6. With activity present but audit nil, hybrid behaves like
// activity-only. Useful in tests and a possible future state if the
// audit store is replaced wholesale.
func TestHybridLastSeenReader_ActivityOnly(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{stamps: map[string]string{"local-codex|hooks": "2026-04-26T11:00:00Z"}},
	}
	got, _ := h.LastSeenByPrincipalSurface("local-codex", "hooks")
	if got != "2026-04-26T11:00:00Z" {
		t.Errorf("got = %q; want activity-only timestamp", got)
	}
	// Pair with no row stays empty rather than erroring.
	if got, _ = h.LastSeenByPrincipalSurface("local-codex", "mcp_http"); got != "" {
		t.Errorf("got = %q; want empty for unknown pair", got)
	}
}

// 7. Both readers parse, with sub-second precision differences. The
// hybrid reader must compare instants, not strings, so an audit value
// with no fractional seconds can still win against an activity value
// from a few millis earlier.
func TestHybridLastSeenReader_NanosecondPrecisionCompared(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-26T10:00:00.500Z"}},
		Audit:    stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-26T10:00:01Z"}},
	}
	got, _ := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if got != "2026-04-26T10:00:01Z" {
		t.Errorf("got = %q; want audit timestamp (0.5s later than activity)", got)
	}
}

// 8. An unparseable timestamp on one side loses to a parseable one
// on the other. The reader must not surface garbage just because the
// "preferred" reader returned a malformed string.
func TestHybridLastSeenReader_UnparseableLosesToParseable(t *testing.T) {
	h := HybridLastSeenReader{
		Activity: stubReader{stamps: map[string]string{"local-codex|mcp_http": "not-a-timestamp"}},
		Audit:    stubReader{stamps: map[string]string{"local-codex|mcp_http": "2026-04-26T10:00:00Z"}},
	}
	got, _ := h.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if got != "2026-04-26T10:00:00Z" {
		t.Errorf("got = %q; want audit timestamp; activity was unparseable", got)
	}
}
