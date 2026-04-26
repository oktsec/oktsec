// Package coverage produces the per-principal, per-surface protection
// matrix the dashboard renders. It does not own any state itself: the
// matrix is derived from the current config (which principals exist and
// what tokens they hold), the per-surface auth posture, and the audit
// trail (last observed activity).
//
// The output of Compute is a flat list of cells. The dashboard renderer
// pivots them into a Principal × Surface table.
package coverage

// CoverageMode is the per-cell label the dashboard surfaces for a
// single (principal, surface) pair. Trust level (authenticated,
// trusted_local, etc.) is reported as a separate field so the matrix
// does not collapse "blocking is possible" and "identity is strong"
// into one value.
type CoverageMode string

const (
	// CoverageProtected: Oktsec sits in the path before the action and
	// can block it. The principal holds a token of the correct type for
	// the surface and the surface itself is enabled.
	CoverageProtected CoverageMode = "protected"

	// CoverageObserved: Oktsec sees telemetry but cannot reliably block.
	// Used for hooks in local profile when no hook token is configured —
	// pre-action hooks would still record activity, but enforcement
	// depends on the client honoring block decisions.
	CoverageObserved CoverageMode = "observed"

	// CoverageBlind: Oktsec knows the surface exists but has no signal
	// for this principal there. Either the surface is disabled, the
	// principal lacks a token of the matching type, or no observed
	// activity links the two.
	CoverageBlind CoverageMode = "blind"
)

// Surface identifies the technical boundary the coverage cell describes.
// String values match resolve.Surface so callers can compare without
// importing the resolver package.
type Surface string

const (
	SurfaceMCPHTTP    Surface = "mcp_http"
	SurfaceHTTPEgress Surface = "http_egress_proxy"
	SurfaceHooks      Surface = "hooks"
)

// AllSurfaces is the canonical iteration order Compute uses; the
// dashboard renders columns in the same order so the matrix reads the
// same way every time.
var AllSurfaces = []Surface{SurfaceMCPHTTP, SurfaceHTTPEgress, SurfaceHooks}

// CoverageCell is one (principal, surface) datapoint in the matrix. The
// dashboard pivots a slice of these into a per-principal row with one
// column per surface.
type CoverageCell struct {
	PrincipalID string `json:"principal_id"`
	ConnectorID string `json:"connector_id"` // inferred from token mix; see connector.go
	Surface     string `json:"surface"`

	// AuthMethod and TrustLevel describe HOW identity is established for
	// this surface. They live next to Coverage instead of inside it so
	// "trusted_local" never gets read as "protected" by accident.
	AuthMethod string `json:"auth_method,omitempty"`
	TrustLevel string `json:"trust_level,omitempty"`

	Coverage CoverageMode `json:"coverage"`

	// Limitation is the one-sentence operator-facing reason a cell is
	// not in the protected state. Examples: "no proxy_basic token
	// configured", "domain-only (HTTPS CONNECT)", "post-action only".
	// Empty when Coverage is protected and there is no caveat.
	Limitation string `json:"limitation,omitempty"`

	// LastSeen is the most recent audit timestamp attributing activity
	// to this principal on this surface (RFC3339). Empty string means
	// the pair has never been observed in the audit trail.
	LastSeen string `json:"last_seen,omitempty"`
}

// AuditReader is the minimal projection of the audit store the coverage
// computer needs. Keeping it narrow lets tests substitute an in-memory
// fake without spinning up a real database.
type AuditReader interface {
	// LastSeenByPrincipalSurface returns the most recent timestamp
	// (RFC3339) for events that match the given principal and surface.
	// Returns "" without an error when there is no matching activity.
	LastSeenByPrincipalSurface(principalID, surface string) (string, error)
}
