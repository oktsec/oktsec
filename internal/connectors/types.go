// Package connectors holds the capability-based connector registry the
// Phase 2B.1 coverage matrix uses to label a principal's runtime
// integration. A "connector" here is the bundle of surfaces, token
// types, auth methods, and event types a known client (or the
// "Custom client" / "Unknown source" buckets) is expected to use.
//
// The registry is deliberately capability-driven, not named-client
// driven: nothing in this package branches on "claude-code" or
// "codex" or any other client name. The dashboard and policy paths
// must keep working when a new client appears in the wild — they
// just see a connector with the matching capability shape.
//
// PR4 ships the in-process built-in registry and the Infer entry
// point Compute uses. PR5 wires the dashboard drill-down on top.
// Future PRs may add a YAML-driven custom connector layer; the
// Registry interface is stable enough for that to slot in without
// touching callers.
package connectors

// SurfaceCapability describes one (surface, token type) pair the
// connector knows how to participate in. The fields are descriptive
// metadata for the dashboard and the inference logic; they are not a
// policy contract on their own. Auth methods and event types are
// listed so a future operator-facing view can show "this connector
// uses bearer_token on mcp_http and emits mcp.tool_call events" with
// stable strings.
type SurfaceCapability struct {
	Surface         string   // resolve.Surface / activity.Surface wire value
	TokenType       string   // config.PrincipalTokenConfig.Type value
	AuthMethods     []string // resolve.AuthMethod wire values the surface honors
	EventTypes      []string // activity.EventType wire values the surface emits
	CanBlock        bool     // true when oktsec sits in the path before action
	DefaultCoverage string   // coverage.CoverageMode wire value when the capability is realized
	Caveat          string   // optional one-sentence display caveat
}

// Connector is the registry record for one integration shape. ID is
// the stable wire value the dashboard pivots on; DisplayName is the
// only operator-visible string. Kind groups connectors for filtering
// without having to enumerate every ID.
type Connector struct {
	ID          string
	DisplayName string
	Kind        string
	Surfaces    []SurfaceCapability
}

// Registry is the contract callers depend on. It hides the storage
// layer (in-process map today, possibly YAML-driven later) and bundles
// the Infer step so coverage code does not have to reach into the
// connector table itself.
type Registry interface {
	// Get returns the connector with the given ID. The bool is false
	// when the ID is not registered; callers should treat that as
	// IDUnknown rather than panicking.
	Get(id string) (Connector, bool)

	// List returns every registered connector. Order is stable and
	// deterministic so dashboard rendering does not flicker.
	List() []Connector

	// Infer chooses the connector that best matches the evidence at
	// hand. activeTokenTypes maps the principal's currently-valid
	// (non-revoked, non-expired) token types to true. observedAuthMethods
	// maps auth methods the principal could plausibly use on at least
	// one surface (e.g. "trusted_loopback" when local-mode loopback is
	// honored anywhere) to true. The implementation must never panic
	// on missing keys; callers may pass nil for either input.
	Infer(activeTokenTypes map[string]bool, observedAuthMethods map[string]bool) Connector
}

// Connector ID constants. Wire values match the Phase 2B.1 spec table.
// Kept exported so callers can compare without re-deriving the strings.
const (
	IDGenericMCPHTTP       = "generic-mcp-http"
	IDGenericEgressProxy   = "generic-egress-proxy"
	IDGenericHooks         = "generic-hooks"
	IDCustomClient         = "custom-client"
	IDLegacyLoopbackHeader = "legacy-loopback-header"
	IDUnknown              = "unknown"
)

// Connector kind constants. Used by Connector.Kind. Kept narrow on
// purpose — new kinds should be added consciously, not from
// free-form strings.
const (
	KindGeneric = "generic"
	KindCustom  = "custom"
	KindLegacy  = "legacy"
	KindUnknown = "unknown"
)
