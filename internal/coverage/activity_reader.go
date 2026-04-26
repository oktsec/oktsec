package coverage

import (
	"context"

	"github.com/oktsec/oktsec/internal/activity"
)

// ActivityLastSeen adapts an activity.Store into the AuditReader
// interface coverage.Compute expects. It exists because activity.Store
// takes a context.Context (its query is async-friendly and may be
// cancelled by an enclosing request) while AuditReader is the older,
// context-free shape coverage was built around.
//
// The adapter passes context.Background to keep the LastSeen lookup
// independent of a request lifecycle: coverage is computed on
// dashboard render, and a client cancellation must not blank a column
// that other in-flight requests are about to read. The underlying
// activity.SQLStore already enforces its own bounded query timeouts,
// so an unbounded background context is safe in practice.
type ActivityLastSeen struct {
	Store activity.Store
}

// LastSeenByPrincipalSurface delegates to the activity store. A nil
// store is a valid no-op state (the dashboard wires this when the
// audit store does not expose a *sql.DB) — return the empty result
// so the hybrid reader can fall back to audit.
func (a ActivityLastSeen) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	if a.Store == nil {
		return "", nil
	}
	return a.Store.LastSeenByPrincipalSurface(context.Background(), principalID, surface)
}
