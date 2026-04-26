package coverage

import (
	"context"
	"time"

	"github.com/oktsec/oktsec/internal/activity"
)

// activityLastSeenTimeout bounds a single activity-store LastSeen
// lookup so a stalled or locked activity DB cannot pin a dashboard
// render. The hybrid reader catches the resulting error and falls
// back to the audit reader, so the operator sees the audit-backed
// value instead of a hung page. 1.5s is generous for a single
// indexed SELECT and tight enough that 3N queries per render
// (principals × surfaces) stay bounded under failure.
const activityLastSeenTimeout = 1500 * time.Millisecond

// ActivityLastSeen adapts an activity.Store into the AuditReader
// interface coverage.Compute expects. It exists because activity.Store
// takes a context.Context (its query is async-friendly and may be
// cancelled by an enclosing request) while AuditReader is the older,
// context-free shape coverage was built around.
//
// The adapter detaches from the inbound HTTP request context on
// purpose: coverage is computed on dashboard render, and a client
// cancellation must not blank a column that other in-flight requests
// are about to read. It then bounds the lookup with its own short
// timeout so a stalled activity store cannot hang the render.
type ActivityLastSeen struct {
	Store activity.Store
}

// LastSeenByPrincipalSurface delegates to the activity store with a
// bounded background context. A nil store is a valid no-op state
// (the dashboard wires this when the audit store does not expose a
// *sql.DB) — return the empty result so the hybrid reader can fall
// back to audit. Errors propagate up so the hybrid reader can swallow
// them and reach for the audit fallback.
func (a ActivityLastSeen) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	if a.Store == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), activityLastSeenTimeout)
	defer cancel()
	return a.Store.LastSeenByPrincipalSurface(ctx, principalID, surface)
}
