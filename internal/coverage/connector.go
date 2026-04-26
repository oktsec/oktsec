package coverage

// Connector identifiers reported in CoverageCell.ConnectorID. Phase 2A
// infers these from the principal's token mix; later phases will move
// to an explicit `connector:` field in PrincipalConfig.
const (
	ConnectorGenericMCPHTTP    = "generic-mcp-http"
	ConnectorGenericEgressProxy = "generic-egress-proxy"
	ConnectorGenericHooks      = "generic-hooks"
	ConnectorCustomClient      = "custom-client"     // multi-surface principal
	ConnectorLegacyLocalHeader = "legacy-local-header"
)

// inferConnectorIDFromActive picks a connector label from the set of
// active token types the principal currently holds. Callers compute the
// active set once with activeTokenTypes (which already filters revoked
// and expired entries) and pass it in here, so an expired-only
// gateway_bearer never ends up labeling the principal as
// generic-mcp-http while Compute correctly marks every surface blind.
func inferConnectorIDFromActive(active map[string]bool) string {
	hasGW := active["gateway_bearer"]
	hasProxy := active["proxy_basic"]
	hasHook := active["hook_bearer"]

	count := 0
	for _, b := range []bool{hasGW, hasProxy, hasHook} {
		if b {
			count++
		}
	}
	switch {
	case count >= 2:
		return ConnectorCustomClient
	case hasGW:
		return ConnectorGenericMCPHTTP
	case hasProxy:
		return ConnectorGenericEgressProxy
	case hasHook:
		return ConnectorGenericHooks
	}
	// No active tokens: the principal exists in config but only relies
	// on the legacy X-Oktsec-Agent header for identity.
	return ConnectorLegacyLocalHeader
}
