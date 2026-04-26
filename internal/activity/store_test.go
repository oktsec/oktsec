package activity

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newTestStore opens an isolated SQLite database under t.TempDir, runs
// the activity migration, and returns the store. Each test gets its
// own file so they do not contend.
func newTestStore(t *testing.T) *SQLStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "activity.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db, DialectSQLite); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewSQLStore(db, DialectSQLite)
}

// validEvent returns the smallest Event that satisfies validate(). Tests
// override fields they care about and rely on the helper for the rest
// so a future required-field addition only updates one place.
func validEvent(id string) Event {
	return Event{
		ID:           id,
		Timestamp:    time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC),
		PrincipalID:  "local-codex",
		Surface:      SurfaceMCPHTTP,
		EventType:    EventMCPToolCall,
		EvidenceType: EvidenceGateway,
		CoverageMode: CoverageProtected,
		Confidence:   100,
	}
}

// 1. Insert + Query round-trips every field. This is the basic
// regression guard: if any column drops out of the INSERT/SELECT
// alignment, the round-trip fails with a missing or shifted value.
func TestSQLStore_InsertQueryRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	in := validEvent("evt-1")
	in.OrgID = "acme"
	in.HostID = "laptop-7"
	in.WorkspaceID = "repo-x"
	in.ReportedActor = "review-subagent"
	in.AuthMethod = "bearer_token"
	in.PrincipalTrustLevel = "authenticated"
	in.ConnectorID = "generic-mcp-http"
	in.ClientID = "claude-code-1"
	in.SessionID = "s1"
	in.RequestID = "r1"
	in.AuditEntryID = "audit-99"
	in.DecisionTraceID = "trace-99"
	in.Status = "allow"
	in.PolicyDecision = "ok"
	in.ResourceType = "mcp_tool"
	in.ResourceID = "files/read_file"
	in.ResourceHash = "sha256:abc"
	in.ResourceLabel = "filesystem.read_file"
	in.EvidenceJSON = `{"k":"v"}`
	in.CreatedAt = time.Date(2026, 4, 26, 10, 0, 5, 0, time.UTC)

	if err := store.Insert(ctx, in); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := store.Query(ctx, Query{PrincipalID: "local-codex"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	out := got[0]
	if out.ID != "evt-1" || out.PrincipalID != "local-codex" {
		t.Errorf("identity round-trip wrong: %+v", out)
	}
	if out.Surface != SurfaceMCPHTTP || out.EventType != EventMCPToolCall ||
		out.EvidenceType != EvidenceGateway || out.CoverageMode != CoverageProtected {
		t.Errorf("typed columns lost in round-trip: %+v", out)
	}
	if out.OrgID != "acme" || out.HostID != "laptop-7" || out.WorkspaceID != "repo-x" {
		t.Errorf("deployment context lost: %+v", out)
	}
	if out.ResourceLabel != "filesystem.read_file" || out.EvidenceJSON != `{"k":"v"}` {
		t.Errorf("resource fields lost: %+v", out)
	}
	if !out.Timestamp.Equal(in.Timestamp) {
		t.Errorf("timestamp lost: got %s want %s", out.Timestamp, in.Timestamp)
	}
}

// 2. Required-field validation rejects malformed events without
// touching the DB. A misbehaving adapter (PR2/3) cannot fill the table
// with rows that have no principal or no surface.
func TestSQLStore_InsertRejectsMissingRequired(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		mut   func(*Event)
		field string
	}{
		{"no_principal", func(e *Event) { e.PrincipalID = "" }, "principal_id"},
		{"no_surface", func(e *Event) { e.Surface = "" }, "surface"},
		{"no_event_type", func(e *Event) { e.EventType = "" }, "event_type"},
		{"no_evidence_type", func(e *Event) { e.EvidenceType = "" }, "evidence_type"},
		{"no_coverage", func(e *Event) { e.CoverageMode = "" }, "coverage_mode"},
		{"unknown_coverage", func(e *Event) { e.CoverageMode = "made-up" }, "unknown coverage_mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := validEvent("evt-" + tc.name)
			tc.mut(&ev)
			err := store.Insert(ctx, ev)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("error = %v; want wrapped ErrInvalidEvent", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error message %q should mention %q", err.Error(), tc.field)
			}
		})
	}
}

// 3. EvidenceJSON is bounded at insert. A malicious or buggy adapter
// cannot persist multi-MB blobs that would bloat the index.
func TestSQLStore_InsertRejectsOversizedEvidence(t *testing.T) {
	store := newTestStore(t)
	ev := validEvent("evt-big")
	ev.EvidenceJSON = strings.Repeat("x", MaxEvidenceJSONBytes+1)
	err := store.Insert(context.Background(), ev)
	if err == nil {
		t.Fatal("oversized evidence should be rejected")
	}
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("error = %v; want wrapped ErrInvalidEvent", err)
	}
}

// 4. Query filters compose: principal + surface returns only the
// matching subset, even when other surfaces share the same principal.
func TestSQLStore_QueryFiltersComposeAcrossPrincipalAndSurface(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	a := validEvent("a")
	a.Surface = SurfaceMCPHTTP
	b := validEvent("b")
	b.Surface = SurfaceHTTPEgressProxy
	b.EventType = EventEgressRequest
	c := validEvent("c")
	c.PrincipalID = "researcher"
	c.Surface = SurfaceMCPHTTP
	for _, e := range []Event{a, b, c} {
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("insert %s: %v", e.ID, err)
		}
	}

	got, err := store.Query(ctx, Query{
		PrincipalID: "local-codex",
		Surface:     string(SurfaceMCPHTTP),
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a" {
		t.Errorf("filter result = %+v; want only event a", ids(got))
	}
}

// 4b. Query.PrincipalIDs filters with an IN clause and AND-combines
// with the other constraints. The dashboard uses this to push a
// connector_id drill-down into SQL: it resolves the connector to the
// set of currently-matching principals and passes them here so the
// LIMIT applies AFTER the connector filter, not before.
func TestSQLStore_QueryPrincipalIDsInClause(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	a := validEvent("a") // local-codex
	b := validEvent("b")
	b.PrincipalID = "researcher"
	c := validEvent("c")
	c.PrincipalID = "third-party"
	for _, e := range []Event{a, b, c} {
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("insert %s: %v", e.ID, err)
		}
	}

	got, err := store.Query(ctx, Query{
		PrincipalIDs: []string{"local-codex", "researcher"},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("PrincipalIDs IN clause returned %d events; want 2 (a + b)", len(got))
	}
	gotIDs := map[string]bool{}
	for _, e := range got {
		gotIDs[e.ID] = true
	}
	if !gotIDs["a"] || !gotIDs["b"] || gotIDs["c"] {
		t.Errorf("returned IDs = %v; want exactly {a, b}", gotIDs)
	}
}

// 4c. Newer events from non-matching principals do not push older
// matching events out of a Limit-bounded result. This is the
// connector_id drill-down regression: with the IN clause pushed into
// SQL, asking for limit=1 of {a, c} where c is newer must return c —
// b ("researcher", newest) is excluded by the filter, not by the
// limit. Without the IN-in-SQL change, the same query would order by
// timestamp first and lose c to a post-filter.
func TestSQLStore_PrincipalIDsLimitAppliesAfterFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	old := validEvent("old")
	old.Timestamp = time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC)
	newish := validEvent("newish")
	newish.PrincipalID = "researcher"
	newish.Timestamp = time.Date(2026, 4, 26, 11, 0, 0, 0, time.UTC) // newest, but not in IN set
	matching := validEvent("matching")
	matching.PrincipalID = "third-party"
	matching.Timestamp = time.Date(2026, 4, 26, 10, 30, 0, 0, time.UTC)
	for _, e := range []Event{old, newish, matching} {
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("insert %s: %v", e.ID, err)
		}
	}

	// Filter to {old, matching}, limit 1: must return matching (the
	// newer of the two), NOT newish (which is newer overall but not
	// in the IN set).
	got, err := store.Query(ctx, Query{
		PrincipalIDs: []string{"local-codex", "third-party"},
		Limit:        1,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].ID != "matching" {
		t.Errorf("limit-with-IN result = %v; want exactly [matching]", ids(got))
	}
}

// 5. Query Limit is bounded: zero or negative inputs default; oversized
// inputs are capped. Forgetting to set Limit cannot accidentally page
// through the entire table.
func TestSQLStore_QueryLimitBounded(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Insert MaxQueryLimit+50 events so the cap is observable.
	total := MaxQueryLimit + 50
	for i := 0; i < total; i++ {
		ev := validEvent("evt-" + intToStr(i))
		ev.Timestamp = time.Date(2026, 4, 26, 10, 0, i, 0, time.UTC)
		if err := store.Insert(ctx, ev); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	zero, _ := store.Query(ctx, Query{PrincipalID: "local-codex"})
	if len(zero) != DefaultQueryLimit {
		t.Errorf("zero limit returned %d; want default %d", len(zero), DefaultQueryLimit)
	}
	too, _ := store.Query(ctx, Query{PrincipalID: "local-codex", Limit: total + 1000})
	if len(too) != MaxQueryLimit {
		t.Errorf("oversized limit returned %d; want capped to %d", len(too), MaxQueryLimit)
	}
}

// 6. LastSeenByPrincipalSurface returns the most recent timestamp for
// the requested pair, and "" without an error when nothing matches.
// Empty inputs short-circuit so callers can iterate hardcoded surface
// lists without crashing on an unset id.
func TestSQLStore_LastSeenByPrincipalSurface(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	older := validEvent("old")
	older.Timestamp = time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	newer := validEvent("new")
	newer.Timestamp = time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC)
	other := validEvent("other-surface")
	other.Surface = SurfaceHTTPEgressProxy
	other.EventType = EventEgressRequest
	other.Timestamp = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	for _, e := range []Event{older, newer, other} {
		_ = store.Insert(ctx, e)
	}

	got, err := store.LastSeenByPrincipalSurface(ctx, "local-codex", string(SurfaceMCPHTTP))
	if err != nil {
		t.Fatalf("last seen: %v", err)
	}
	if !strings.HasPrefix(got, "2026-04-26T10:00:00") {
		t.Errorf("mcp_http last seen = %q; want the newer event timestamp", got)
	}

	miss, err := store.LastSeenByPrincipalSurface(ctx, "ghost", string(SurfaceMCPHTTP))
	if err != nil || miss != "" {
		t.Errorf("missing principal should be empty/no-error; got %q, %v", miss, err)
	}
	empty, err := store.LastSeenByPrincipalSurface(ctx, "", string(SurfaceMCPHTTP))
	if err != nil || empty != "" {
		t.Errorf("empty principal should be empty/no-error; got %q, %v", empty, err)
	}
}

// 7. ListByCoverageCell returns the most recent N events for a
// (principal, surface) pair, newest first. Powers the dashboard
// drill-down in PR5.
func TestSQLStore_ListByCoverageCell(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		ev := validEvent("evt-" + intToStr(i))
		ev.Timestamp = time.Date(2026, 4, 26, 10, i, 0, 0, time.UTC)
		_ = store.Insert(ctx, ev)
	}
	got, err := store.ListByCoverageCell(ctx, "local-codex", string(SurfaceMCPHTTP), 3)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d; want 3", len(got))
	}
	// Newest first: timestamps must be strictly descending.
	for i := 1; i < len(got); i++ {
		if !got[i-1].Timestamp.After(got[i].Timestamp) {
			t.Errorf("ordering broken at %d: %s vs %s", i, got[i-1].Timestamp, got[i].Timestamp)
		}
	}
}

// 8. Migrate is idempotent: calling it twice is a no-op and does not
// drop or duplicate the table. Surface adapters can call it on every
// startup without coordination.
func TestMigrate_Idempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "activity.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := Migrate(db, DialectSQLite); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := Migrate(db, DialectSQLite); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	store := NewSQLStore(db, DialectSQLite)
	if err := store.Insert(context.Background(), validEvent("evt-1")); err != nil {
		t.Errorf("insert after double-migrate failed: %v", err)
	}
}

// 9. Unknown dialect is rejected at migrate time so a typo in
// configuration cannot create a half-functional store.
func TestMigrate_UnknownDialect(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "activity.db")
	db, _ := sql.Open("sqlite", dbPath)
	defer func() { _ = db.Close() }()
	if err := Migrate(db, "mariadb"); err == nil {
		t.Error("expected error for unknown dialect")
	}
}

// helpers ---------------------------------------------------------------

func ids(es []Event) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}
