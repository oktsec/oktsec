package coverage

// HybridLastSeenReader prefers an activity-backed reader for the
// LastSeen attribution and falls back to an audit-backed reader when
// activity has no row for the (principal, surface) pair. Either field
// may be nil — callers can roll out the activity store incrementally
// without touching coverage:
//
//   - Activity nil, Audit non-nil: behaves identically to Phase 2A.
//   - Activity non-nil, Audit nil: activity-only (useful in tests).
//   - Both non-nil: activity wins when it has a row, audit fills the
//     long tail for events from before activity was wired up.
//   - Both nil: every cell ends up with empty LastSeen.
//
// The reader satisfies AuditReader directly so coverage.Compute can
// accept it without a wrapper.
type HybridLastSeenReader struct {
	Activity AuditReader
	Audit    AuditReader
}

// LastSeenByPrincipalSurface returns the most recent timestamp the
// hybrid reader can attribute to the (principal, surface) pair. The
// activity reader wins when it has a non-empty row; an empty result
// from activity is treated as "no activity-backed data" rather than
// an authoritative miss, so the audit fallback still gets a chance.
//
// Errors from the activity reader are NOT propagated as failures —
// they trigger the audit fallback the same way an empty row does.
// The reasoning: activity is best-effort; an outage there must not
// blank the LastSeen column the operator already trusts.
func (h HybridLastSeenReader) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	if h.Activity != nil {
		ts, err := h.Activity.LastSeenByPrincipalSurface(principalID, surface)
		if err == nil && ts != "" {
			return ts, nil
		}
	}
	if h.Audit != nil {
		return h.Audit.LastSeenByPrincipalSurface(principalID, surface)
	}
	return "", nil
}
