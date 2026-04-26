package coverage

import "github.com/oktsec/oktsec/internal/connectors"

// Connector identifiers reported in CoverageCell.ConnectorID. Re-exported
// from the connectors package so callers in coverage can compare without
// having to import a second package, and so existing tests keep working
// across the registry refactor.
const (
	ConnectorGenericMCPHTTP       = connectors.IDGenericMCPHTTP
	ConnectorGenericEgressProxy   = connectors.IDGenericEgressProxy
	ConnectorGenericHooks         = connectors.IDGenericHooks
	ConnectorCustomClient         = connectors.IDCustomClient
	ConnectorLegacyLoopbackHeader = connectors.IDLegacyLoopbackHeader
	ConnectorUnknown              = connectors.IDUnknown
)
