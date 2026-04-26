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
	case ConnectorLegacyLocalHeader:
		return "Legacy loopback header"
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

// LimitationShortLabel reduces the full Limitation sentence to a small
// inline tag the cell can show under the badge without bloating the
// row. The full text remains available as a tooltip; this is just a
// summary that keeps the matrix scannable.
//
// Returns empty when the cell has no caveat (clean Protected, or a
// Blind cell whose Limitation is already self-explanatory).
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
	case strings.Contains(lim, "domain-only"):
		return "Domain only"
	case strings.Contains(lim, "request bodies inspected"):
		return "Request bodies inspected"
	case strings.Contains(lim, "plain http bodies inspected"):
		return "HTTP bodies inspected"
	}
	// Unknown limitation: take the first clause so something inline
	// still appears; the tooltip carries the full detail.
	if i := strings.IndexAny(lim, ".—;"); i > 0 {
		return strings.TrimSpace(c.Limitation[:i])
	}
	return c.Limitation
}
