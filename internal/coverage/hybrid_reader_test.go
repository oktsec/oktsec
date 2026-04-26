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

// 1. When the activity reader has a row, the hybrid reader returns
// it and never consults the audit reader. This is the common path
// once activity has been running for a while.
func TestHybridLastSeenReader_ActivityWins(t *testing.T) {
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

// 2. When activity has no row for the pair, the audit fallback fills
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

// 3. An activity error is treated the same as an empty row: the audit
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

// 4. With both readers nil the hybrid returns empty cleanly. This is
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

// 5. With activity present but audit nil, hybrid behaves like
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
