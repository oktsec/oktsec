package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store is the persistence layer for activity events. Implementations
// must be safe for concurrent use; SQLStore is the production
// implementation backed by the same DB handle as audit.Store.
//
// Insert is on the request hot path. Implementations must:
//   - validate required fields and reject malformed events;
//   - never block on aggregate queries;
//   - never panic on a malformed evidence blob — bad rows return errors
//     so the caller can log and continue without crashing the surface.
//
// Query and ListByCoverageCell are dashboard-side and may do bounded
// I/O; both honor DefaultQueryLimit / MaxQueryLimit so a forgotten
// limit cannot exhaust resources.
type Store interface {
	Insert(ctx context.Context, e Event) error
	Query(ctx context.Context, q Query) ([]Event, error)
	LastSeenByPrincipalSurface(ctx context.Context, principalID, surface string) (string, error)
	ListByCoverageCell(ctx context.Context, principalID, surface string, limit int) ([]Event, error)
}

// ErrInvalidEvent is returned by Insert when required fields are
// missing, EvidenceJSON is too large, or coverage_mode is unknown.
// Callers treat this as "drop the event, log a warning" — never as
// "fail the request".
var ErrInvalidEvent = errors.New("activity: invalid event")

// SQLStore is the database-backed Store. It accepts the same *sql.DB
// the audit store uses so activity_events lives beside audit_log
// without a second DSN or migration tool.
type SQLStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewSQLStore wraps a database handle. The caller is responsible for
// running Migrate before issuing inserts; failing to do so will surface
// a "no such table" error on the first Insert.
func NewSQLStore(db *sql.DB, d Dialect) *SQLStore {
	if d == "" {
		d = DialectSQLite
	}
	return &SQLStore{db: db, dialect: d}
}

// validate enforces the invariants that callers must respect. Each
// failure returns a wrapped ErrInvalidEvent so callers can decide
// whether to log or alert.
func validate(e Event) error {
	switch {
	case e.PrincipalID == "":
		return fmt.Errorf("%w: principal_id required", ErrInvalidEvent)
	case e.Surface == "":
		return fmt.Errorf("%w: surface required", ErrInvalidEvent)
	case e.EventType == "":
		return fmt.Errorf("%w: event_type required", ErrInvalidEvent)
	case e.EvidenceType == "":
		return fmt.Errorf("%w: evidence_type required", ErrInvalidEvent)
	case e.CoverageMode == "":
		return fmt.Errorf("%w: coverage_mode required", ErrInvalidEvent)
	}
	switch e.CoverageMode {
	case CoverageProtected, CoverageObserved, CoverageBlind:
	default:
		return fmt.Errorf("%w: unknown coverage_mode %q", ErrInvalidEvent, e.CoverageMode)
	}
	if len(e.EvidenceJSON) > MaxEvidenceJSONBytes {
		return fmt.Errorf("%w: evidence_json exceeds %d bytes (got %d)",
			ErrInvalidEvent, MaxEvidenceJSONBytes, len(e.EvidenceJSON))
	}
	return nil
}

// Insert persists one event. Required fields are validated; missing or
// malformed events return ErrInvalidEvent without touching the DB so a
// misbehaving adapter cannot fill the table with garbage rows.
func (s *SQLStore) Insert(ctx context.Context, e Event) error {
	if err := validate(e); err != nil {
		return err
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.EvidenceJSON == "" {
		e.EvidenceJSON = "{}"
	}
	q := `INSERT INTO activity_events (
        id, timestamp, org_id, host_id, workspace_id,
        principal_id, reported_actor, auth_method, principal_trust_level,
        connector_id, client_id, surface, event_type, evidence_type,
        session_id, request_id, audit_entry_id, decision_trace_id,
        status, policy_decision, coverage_mode, confidence,
        resource_type, resource_id, resource_hash, resource_label,
        evidence_json, created_at
    ) VALUES (` + insertPlaceholders(s.dialect, 28) + `)`
	_, err := s.db.ExecContext(ctx, q,
		e.ID, e.Timestamp.UTC().Format(time.RFC3339Nano), e.OrgID, e.HostID, e.WorkspaceID,
		e.PrincipalID, e.ReportedActor, e.AuthMethod, e.PrincipalTrustLevel,
		e.ConnectorID, e.ClientID, string(e.Surface), string(e.EventType), string(e.EvidenceType),
		e.SessionID, e.RequestID, e.AuditEntryID, e.DecisionTraceID,
		e.Status, e.PolicyDecision, string(e.CoverageMode), e.Confidence,
		e.ResourceType, e.ResourceID, e.ResourceHash, e.ResourceLabel,
		e.EvidenceJSON, e.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("activity: insert: %w", err)
	}
	return nil
}

// selectColumns is the canonical SELECT list. Centralized so Query and
// ListByCoverageCell scan into the same field order.
const selectColumns = `id, timestamp, org_id, host_id, workspace_id,
    principal_id, reported_actor, auth_method, principal_trust_level,
    connector_id, client_id, surface, event_type, evidence_type,
    session_id, request_id, audit_entry_id, decision_trace_id,
    status, policy_decision, coverage_mode, confidence,
    resource_type, resource_id, resource_hash, resource_label,
    evidence_json, created_at`

// Query returns events matching q, applying the bounded limit policy.
// Time bounds are inclusive when set; zero time values are ignored.
func (s *SQLStore) Query(ctx context.Context, q Query) ([]Event, error) {
	limit := boundLimit(q.Limit)
	where, args := buildWhere(s.dialect, q)
	sqlStr := "SELECT " + selectColumns + " FROM activity_events" + where +
		" ORDER BY timestamp DESC LIMIT " + fmt.Sprintf("%d", limit)
	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("activity: query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanEvents(rows)
}

// LastSeenByPrincipalSurface returns the most recent event timestamp
// (RFC3339) for the (principal, surface) pair. Returns "" without an
// error when nothing matches — that maps to "No activity recorded" in
// the dashboard rather than a noisy log line.
func (s *SQLStore) LastSeenByPrincipalSurface(ctx context.Context, principalID, surface string) (string, error) {
	if principalID == "" || surface == "" {
		return "", nil
	}
	q := "SELECT MAX(timestamp) FROM activity_events WHERE principal_id = " +
		placeholder(s.dialect, 1) + " AND surface = " + placeholder(s.dialect, 2)
	var ts sql.NullString
	if err := s.db.QueryRowContext(ctx, q, principalID, surface).Scan(&ts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("activity: last seen: %w", err)
	}
	return ts.String, nil
}

// ListByCoverageCell powers the dashboard drill-down: the most recent
// `limit` events for one (principal, surface) cell, newest first.
// Caller-supplied limit is bounded by MaxQueryLimit.
func (s *SQLStore) ListByCoverageCell(ctx context.Context, principalID, surface string, limit int) ([]Event, error) {
	if principalID == "" || surface == "" {
		return nil, nil
	}
	limit = boundLimit(limit)
	q := "SELECT " + selectColumns + " FROM activity_events" +
		" WHERE principal_id = " + placeholder(s.dialect, 1) +
		" AND surface = " + placeholder(s.dialect, 2) +
		" ORDER BY timestamp DESC LIMIT " + fmt.Sprintf("%d", limit)
	rows, err := s.db.QueryContext(ctx, q, principalID, surface)
	if err != nil {
		return nil, fmt.Errorf("activity: list by cell: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanEvents(rows)
}

// boundLimit applies the public bounds: zero/negative inputs become the
// default; oversized inputs are capped to the maximum. No errors —
// silently bounding is friendlier than a 500 for a typo'd limit.
func boundLimit(n int) int {
	if n <= 0 {
		return DefaultQueryLimit
	}
	if n > MaxQueryLimit {
		return MaxQueryLimit
	}
	return n
}

// buildWhere assembles the WHERE clause for Query. Returns the SQL
// fragment (with leading " WHERE " or "" if no filters) and its
// argument list, in placeholder-position order.
func buildWhere(d Dialect, q Query) (string, []any) {
	var clauses []string
	var args []any
	add := func(col string, val string) {
		if val == "" {
			return
		}
		clauses = append(clauses, col+" = "+placeholder(d, len(args)+1))
		args = append(args, val)
	}
	add("principal_id", q.PrincipalID)
	if len(q.PrincipalIDs) > 0 {
		// IN clause for the multi-principal filter the dashboard's
		// connector_id drill-down uses. Each value gets its own
		// placeholder so the dialect-aware placeholder() keeps
		// SQLite "?" and Postgres "$N" both correct.
		ph := make([]string, len(q.PrincipalIDs))
		for i, id := range q.PrincipalIDs {
			ph[i] = placeholder(d, len(args)+1)
			args = append(args, id)
		}
		clauses = append(clauses, "principal_id IN ("+strings.Join(ph, ", ")+")")
	}
	add("surface", q.Surface)
	add("connector_id", q.ConnectorID)
	add("workspace_id", q.WorkspaceID)
	add("session_id", q.SessionID)
	add("coverage_mode", q.Coverage)
	if !q.Since.IsZero() {
		clauses = append(clauses, "timestamp >= "+placeholder(d, len(args)+1))
		args = append(args, q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		clauses = append(clauses, "timestamp <= "+placeholder(d, len(args)+1))
		args = append(args, q.Until.UTC().Format(time.RFC3339Nano))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// insertPlaceholders builds "?, ?, ..., ?" (SQLite) or "$1, $2, ..., $N"
// (Postgres) for an INSERT ... VALUES clause with n columns.
func insertPlaceholders(d Dialect, n int) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = placeholder(d, i+1)
	}
	return strings.Join(parts, ", ")
}

// scanEvents reads a *sql.Rows into a []Event using the canonical
// column order. Scan failures abort the whole batch rather than
// returning partial results — partial rows are worse than none.
func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		var ts, createdAt string
		var surface, eventType, evidenceType, coverageMode string
		if err := rows.Scan(
			&e.ID, &ts, &e.OrgID, &e.HostID, &e.WorkspaceID,
			&e.PrincipalID, &e.ReportedActor, &e.AuthMethod, &e.PrincipalTrustLevel,
			&e.ConnectorID, &e.ClientID, &surface, &eventType, &evidenceType,
			&e.SessionID, &e.RequestID, &e.AuditEntryID, &e.DecisionTraceID,
			&e.Status, &e.PolicyDecision, &coverageMode, &e.Confidence,
			&e.ResourceType, &e.ResourceID, &e.ResourceHash, &e.ResourceLabel,
			&e.EvidenceJSON, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("activity: scan: %w", err)
		}
		// Timestamp parsing is lenient: accept both RFC3339 and the
		// nanosecond variant we write so a row inserted by an older
		// release can still be read.
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, ts); err == nil {
			e.Timestamp = t
		}
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			e.CreatedAt = t
		} else if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			e.CreatedAt = t
		}
		e.Surface = Surface(surface)
		e.EventType = EventType(eventType)
		e.EvidenceType = EvidenceType(evidenceType)
		e.CoverageMode = CoverageMode(coverageMode)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("activity: rows: %w", err)
	}
	return out, nil
}
