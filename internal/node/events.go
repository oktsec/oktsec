package node

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

// Event shipping: the node's audit trail is the live record of what
// the proxy actually did. `cloud sync` ships NEW entries to the
// control plane in batches, REDACTED at the analyst level: agent
// names, verdicts, redacted rule findings, latency — never message
// content, tool arguments, intents or delegation chains. The cursor
// is the last shipped timestamp; overlap at the boundary is fine
// because the receiver dedupes on entry ID.

// SchemaEvents freezes the events batch shape.
const SchemaEvents = "node_events.v1"

// EventsBatch is the wire shape POSTed to the control plane.
type EventsBatch struct {
	SchemaVersion string                `json:"schema_version"`
	NodeID        string                `json:"node_id"`
	Entries       []audit.RedactedEntry `json:"entries"`
}

// CollectRecentEvents reads audit entries past the cursor, redacted
// for export, and returns them with the new cursor. The cursor is
// "timestamp|id" of the last shipped entry ("" = everything): the id
// tiebreak makes same-second batches safe — a 500-row batch cutting
// through a busy second, or a late row in an already-shipped second,
// ships on the next cycle instead of being skipped forever.
// A missing or unreadable audit database is a clean no-op: nodes
// without a proxy runtime have no events, not an error.
func CollectRecentEvents(cfgPath, dbPathOverride, cursor string, limit int) ([]audit.RedactedEntry, string, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// No config = no proxy = no events.
		return nil, cursor, nil
	}
	// Same guard as the snapshot builder: a Postgres-backed install
	// must not have a stale local SQLite file shipped as live
	// telemetry.
	if cfg != nil && strings.EqualFold(cfg.DBBackend, "postgres") {
		return nil, cursor, nil
	}
	dbPath := dbPathOverride
	if dbPath == "" {
		dbPath = resolveSnapshotDBPath(cfg)
	}
	if avail := inspectSQLiteAvailability(dbPath); !avail.Available {
		return nil, cursor, nil
	}
	db, err := openSQLiteReadOnly(dbPath)
	if err != nil {
		return nil, cursor, nil
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exists, err := sqliteTableExists(ctx, db, "audit_log")
	if err != nil || !exists {
		return nil, cursor, nil
	}

	where, args := "", []any{}
	if cursor != "" {
		curTS, curID := cursor, ""
		if i := strings.IndexByte(cursor, '|'); i >= 0 {
			curTS, curID = cursor[:i], cursor[i+1:]
		}
		where = "WHERE (timestamp > ? OR (timestamp = ? AND id > ?))"
		args = append(args, curTS, curTS, curID)
	}
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
		SELECT id, timestamp, COALESCE(from_agent,''), COALESCE(to_agent,''),
		       COALESCE(content_hash,''), COALESCE(signature_verified,0),
		       COALESCE(status,''), COALESCE(rules_triggered,''),
		       COALESCE(policy_decision,''), COALESCE(latency_ms,0)
		FROM audit_log %s ORDER BY timestamp ASC, id ASC LIMIT ?`, where), args...)
	if err != nil {
		return nil, cursor, fmt.Errorf("events query: %w", err)
	}
	defer rows.Close()

	var out []audit.RedactedEntry
	last := cursor
	for rows.Next() {
		var e audit.Entry
		var sigVerified sql.NullInt64
		var latency sql.NullInt64
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.FromAgent, &e.ToAgent,
			&e.ContentHash, &sigVerified, &e.Status, &e.RulesTriggered,
			&e.PolicyDecision, &latency); err != nil {
			return nil, cursor, fmt.Errorf("events scan: %w", err)
		}
		e.SignatureVerified = int(sigVerified.Int64)
		e.LatencyMs = latency.Int64
		out = append(out, audit.Redact(e, audit.RedactAnalyst))
		last = e.Timestamp + "|" + e.ID
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, err
	}
	return out, last, nil
}
