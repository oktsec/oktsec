package coverage

import "time"

// HybridLastSeenReader prefers an activity-backed reader for the
// LastSeen attribution but always cross-checks the audit-backed
// reader and returns whichever timestamp represents the later moment
// in time. Either field may be nil — callers can roll out the
// activity store incrementally without touching coverage:
//
//   - Activity nil, Audit non-nil: behaves identically to Phase 2A.
//   - Activity non-nil, Audit nil: activity-only.
//   - Both non-nil: the later of the two parsed timestamps wins.
//   - Both nil: every cell ends up with empty LastSeen.
//
// The reader satisfies AuditReader directly so coverage.Compute can
// accept it without a wrapper.
type HybridLastSeenReader struct {
	Activity AuditReader
	Audit    AuditReader
}

// LastSeenByPrincipalSurface returns the most recent timestamp the
// hybrid reader can attribute to the (principal, surface) pair. Both
// readers are queried when both are configured: activity writes are
// async and best-effort, so audit can carry a newer row right after
// an activity miss or a delayed insert. Returning the activity value
// blindly would surface a stale "Last seen" on the dashboard, so the
// reader compares the two timestamps and returns the later one.
//
// Errors from either reader are NOT propagated as failures — the
// other reader still gets a chance. Activity is best-effort; an
// outage there must not blank the LastSeen column the operator
// already trusts. Unparseable timestamps lose to parseable ones; if
// neither parses, the audit value wins (it is the compliance trail
// and is the safer source for operator-visible state).
func (h HybridLastSeenReader) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	activityTS := readLastSeenQuiet(h.Activity, principalID, surface)
	auditTS := readLastSeenQuiet(h.Audit, principalID, surface)
	return pickLatestTimestamp(activityTS, auditTS), nil
}

// readLastSeenQuiet returns the LastSeen string for the given reader
// or empty when the reader is nil or returns an error. Errors are
// swallowed on purpose: a transient activity-store stall or a future
// audit-store hiccup must not blank the LastSeen column for an
// operator who is already looking at the matrix.
func readLastSeenQuiet(r AuditReader, principalID, surface string) string {
	if r == nil {
		return ""
	}
	ts, err := r.LastSeenByPrincipalSurface(principalID, surface)
	if err != nil {
		return ""
	}
	return ts
}

// pickLatestTimestamp returns whichever of the two RFC3339 strings
// represents the later moment in time. Conservative on parse errors:
//
//   - Empty string loses to any non-empty value.
//   - Both parse: later instant wins.
//   - One parses, one does not: the parseable value wins (never
//     surface garbage just because the other reader got a row in).
//   - Neither parses, both non-empty: the audit value wins because it
//     is the compliance trail; when both are wrong we prefer the more
//     conservative source.
func pickLatestTimestamp(activityTS, auditTS string) string {
	if activityTS == "" {
		return auditTS
	}
	if auditTS == "" {
		return activityTS
	}
	ta, errA := parseLastSeen(activityTS)
	tb, errB := parseLastSeen(auditTS)
	switch {
	case errA == nil && errB == nil:
		if tb.After(ta) {
			return auditTS
		}
		return activityTS
	case errA == nil:
		return activityTS
	case errB == nil:
		return auditTS
	}
	return auditTS
}

// parseLastSeen accepts both RFC3339 (audit's format) and
// RFC3339Nano (what activity may emit when the wall clock has nanos).
// time.RFC3339Nano alone does not match plain RFC3339 with no
// fractional seconds, so the fallback is required.
func parseLastSeen(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
