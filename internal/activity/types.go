// Package activity stores normalized runtime evidence for the dashboard
// coverage matrix and (later) the activity graph. It sits beside the
// tamper-evident audit log: audit remains the compliance trail, activity
// is the product/analytics substrate.
//
// Surface adapters (gateway, forward proxy, hooks) write one Event per
// observed interaction after the security decision has been made and the
// audit row exists. The Store API never appears in the policy hot path —
// callers must treat write failures as "drop the activity row, keep the
// security decision" so an activity outage cannot deny service.
package activity

import "time"

// Surface identifies the technical boundary that produced an event.
// String values match coverage.Surface and resolve.Surface so callers
// can compare across packages without an import cycle.
type Surface string

const (
	SurfaceMCPHTTP         Surface = "mcp_http"
	SurfaceHTTPEgressProxy Surface = "http_egress_proxy"
	SurfaceHooks           Surface = "hooks"
)

// CoverageMode is what the dashboard claims for a single observed
// event. The aggregated per-(principal, surface) coverage cell is
// derived from these — consistent vocabulary across the two layers.
type CoverageMode string

const (
	CoverageProtected CoverageMode = "protected"
	CoverageObserved  CoverageMode = "observed"
	CoverageBlind     CoverageMode = "blind"
)

// EventType is the operation an event represents. Kept narrow on
// purpose; new event types should be added consciously rather than
// allowing free-form strings.
type EventType string

const (
	EventMCPToolCall   EventType = "mcp.tool_call"
	EventEgressRequest EventType = "egress.request"
	EventHookEvent     EventType = "hook.event"
)

// EvidenceType records which surface adapter wrote the event. Matches
// the surface 1:1 today but kept separate so a later release can ingest
// observed-only telemetry from log adapters without conflating it with
// gateway-protected evidence.
type EvidenceType string

const (
	EvidenceGateway EvidenceType = "gateway"
	EvidenceProxy   EvidenceType = "proxy"
	EvidenceHook    EvidenceType = "hook"
)

// Event is one normalized activity record. Field semantics are
// documented in the Phase 2B.1 spec; the short version:
//
//   - PrincipalID is the policy identity (token-authenticated, trusted
//     local, or "unknown" only where the surface accepts unauthenticated
//     local telemetry). Never populated from reported actor alone.
//   - ReportedActor is display/correlation metadata; never overrides the
//     principal for any policy or coverage decision.
//   - Resource* describe the target (tool, domain, hook event). Labels
//     are humanized and redacted by the writer; raw secrets and full
//     sensitive URLs are not persisted.
//   - EvidenceJSON is a small bounded blob for surface-specific metadata.
//     The writer is responsible for redaction; the store enforces a size cap.
//
// Confidence is a hint for the dashboard, not a policy input:
//
//	100  token-authenticated direct surface evidence
//	 80  trusted local loopback evidence
//	 60  authenticated hook post-action evidence
//	 40  unauthenticated local observed telemetry
//	0-20 unknown or malformed evidence kept for diagnostics
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	// Deployment context. Empty values are valid in local mode.
	OrgID       string `json:"org_id,omitempty"`
	HostID      string `json:"host_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`

	// Identity provenance.
	PrincipalID         string `json:"principal_id"`
	ReportedActor       string `json:"reported_actor,omitempty"`
	AuthMethod          string `json:"auth_method,omitempty"`
	PrincipalTrustLevel string `json:"principal_trust_level,omitempty"`

	// Connector and surface.
	ConnectorID  string       `json:"connector_id,omitempty"`
	ClientID     string       `json:"client_id,omitempty"`
	Surface      Surface      `json:"surface"`
	EventType    EventType    `json:"event_type"`
	EvidenceType EvidenceType `json:"evidence_type"`

	// Session / correlation.
	SessionID       string `json:"session_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	AuditEntryID    string `json:"audit_entry_id,omitempty"`
	DecisionTraceID string `json:"decision_trace_id,omitempty"`

	// Security outcome.
	Status         string       `json:"status,omitempty"`
	PolicyDecision string       `json:"policy_decision,omitempty"`
	CoverageMode   CoverageMode `json:"coverage_mode"`
	Confidence     int          `json:"confidence"`

	// Resource. ResourceLabel is humanized + redacted by the writer.
	ResourceType  string `json:"resource_type,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
	ResourceHash  string `json:"resource_hash,omitempty"`
	ResourceLabel string `json:"resource_label,omitempty"`

	// EvidenceJSON is a bounded, redacted blob the surface adapter owns.
	// The store enforces a size cap (see store.go) but does not parse it.
	EvidenceJSON string `json:"evidence_json,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// Query filters Store.Query. Zero-valued fields are ignored.
//
// Limit defaults to DefaultQueryLimit and is capped at MaxQueryLimit so
// no caller can ask for an unbounded result set — even a forgotten limit
// will not exhaust memory or DB resources.
type Query struct {
	PrincipalID string
	Surface     string
	ConnectorID string
	WorkspaceID string
	SessionID   string
	Coverage    string
	Since       time.Time
	Until       time.Time
	Limit       int
}

// Bounds enforced by the Store implementation on every Query.
const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 500

	// MaxEvidenceJSONBytes caps EvidenceJSON at insert time. Larger
	// payloads are rejected so a misbehaving adapter cannot fill the
	// table with multi-MB blobs. The cap is generous enough for typical
	// hook/gateway/proxy metadata and tight enough that one event row
	// stays small in any normal index.
	MaxEvidenceJSONBytes = 8 * 1024
)
