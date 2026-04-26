package coverage

import "strings"

// ConnectorDisplayName turns a machine connector id into the label the
// dashboard renders. Returns the id verbatim when it is not in the
// catalog, so adding a new connector cannot crash the table.
func ConnectorDisplayName(id string) string {
	switch id {
	case ConnectorGenericMCPHTTP:
		return "Generic MCP HTTP"
	case ConnectorGenericEgressProxy:
		return "Generic egress proxy"
	case ConnectorGenericHooks:
		return "Generic hooks"
	case ConnectorCustomClient:
		return "Custom client"
	case ConnectorLegacyLoopbackHeader:
		return "Legacy loopback header"
	case ConnectorUnknown:
		return "Unknown source"
	}
	return id
}

// AuthMethodDisplayName humanizes one auth method id for the Identity
// column. Joining is the caller's job; this only formats one token.
func AuthMethodDisplayName(method string) string {
	switch method {
	case "bearer_token":
		return "Bearer token"
	case "proxy_token":
		return "Proxy token"
	case "hook_token":
		return "Hook token"
	case "trusted_loopback":
		return "Loopback header"
	case "":
		return ""
	}
	return method
}

// CoverageDisplayName is the title-case label for the badge. Observed
// gets an explicit "only" suffix so the badge color cannot read as
// stronger than it is.
func CoverageDisplayName(c CoverageMode) string {
	switch c {
	case CoverageProtected:
		return "Protected"
	case CoverageObserved:
		return "Observed only"
	case CoverageBlind:
		return "Blind"
	}
	return string(c)
}

// AllowedShortLabels is the closed set of short labels a coverage
// cell may show under the badge. The dashboard UX spec keeps this
// list small on purpose so the matrix stays scannable: any
// limitation that does not map cleanly into one of these labels
// shows nothing inline, and the operator opens the drawer for the
// full sentence. A test asserts every value LimitationShortLabel
// returns is either empty or in this set, so a future addition has
// to update both places consciously.
var AllowedShortLabels = []string{
	"Surface off",
	"Loopback only",
	"No token",
	"Telemetry only",
	"Pre-action only",
	"Post-action only",
	"Domain only",
}

// LimitationShortLabel reduces the full Limitation sentence to one
// of the AllowedShortLabels. Returns empty when the limitation does
// not map to a label in that set — long copy never lands inside a
// table cell. The full sentence remains in the badge tooltip and
// in the drill-down drawer for cases that need it.
//
// Case order matters: hook limitations describe both the pre- and
// post-action stages in a single sentence ("pre-action hooks block
// when client honors the decision; post-action hooks are observed
// only"), so the more specific "pre-action hooks block" branch must
// run before any bare "post-action" check.
//
// "Domain only" only fires for the pure CONNECT-tunneled case; the
// protected-egress sentences that mention "domain-only" as one half
// of a longer caveat ("bodies inspected ... HTTPS CONNECT is
// domain-only ...") fall through to empty so the cell stays clean
// and the drawer carries the full explanation.
func LimitationShortLabel(c CoverageCell) string {
	if c.Limitation == "" {
		return ""
	}
	lim := strings.ToLower(c.Limitation)
	switch {
	case strings.Contains(lim, "gateway not enabled"),
		strings.Contains(lim, "forward proxy not enabled"),
		strings.Contains(lim, "gateway disabled"):
		return "Surface off"
	case strings.Contains(lim, "loopback header only"):
		return "Loopback only"
	case strings.Contains(lim, "no gateway_bearer token"),
		strings.Contains(lim, "no proxy_basic token"),
		strings.Contains(lim, "no hook_bearer token; surface requires"):
		return "No token"
	case strings.Contains(lim, "no hook_bearer token; events accepted"):
		return "Telemetry only"
	case strings.Contains(lim, "pre-action hooks block"):
		return "Pre-action only"
	case strings.Contains(lim, "post-action hooks") &&
		!strings.Contains(lim, "pre-action"):
		return "Post-action only"
	case strings.HasPrefix(lim, "domain-only"):
		return "Domain only"
	}
	// No mapping. Keep the cell quiet and let the drawer carry the
	// full explanation when the operator clicks in.
	return ""
}
