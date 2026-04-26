package connectors

// builtinConnectors returns a fresh map of the built-in connector
// definitions. The returned map is the registry's authoritative state;
// callers receive Connector values (not pointers), so they cannot
// mutate the registered SurfaceCapability slices accidentally.
//
// Auth method strings reference resolve.AuthMethod; event type
// strings reference activity.EventType. Both are duplicated here as
// string literals (rather than imported) to keep this package free of
// upstream dependencies — the registry is meant to be the leaf.
func builtinConnectors() map[string]Connector {
	return map[string]Connector{
		IDGenericMCPHTTP: {
			ID:          IDGenericMCPHTTP,
			DisplayName: "Generic MCP HTTP",
			Kind:        KindGeneric,
			Surfaces: []SurfaceCapability{{
				Surface:         "mcp_http",
				TokenType:       "gateway_bearer",
				AuthMethods:     []string{"bearer_token"},
				EventTypes:      []string{"mcp.tool_call"},
				CanBlock:        true,
				DefaultCoverage: "protected",
			}},
		},
		IDGenericEgressProxy: {
			ID:          IDGenericEgressProxy,
			DisplayName: "Generic egress proxy",
			Kind:        KindGeneric,
			Surfaces: []SurfaceCapability{{
				Surface:         "http_egress_proxy",
				TokenType:       "proxy_basic",
				AuthMethods:     []string{"proxy_token"},
				EventTypes:      []string{"egress.request"},
				CanBlock:        true,
				DefaultCoverage: "protected",
				Caveat:          "HTTPS CONNECT is domain-only unless body inspection is enabled",
			}},
		},
		IDGenericHooks: {
			ID:          IDGenericHooks,
			DisplayName: "Generic hooks",
			Kind:        KindGeneric,
			Surfaces: []SurfaceCapability{{
				Surface:         "hooks",
				TokenType:       "hook_bearer",
				AuthMethods:     []string{"hook_token"},
				EventTypes:      []string{"hook.event"},
				CanBlock:        true, // pre-action only; coverage helper enforces stage
				DefaultCoverage: "protected",
				Caveat:          "post-action hooks are observed only",
			}},
		},
		IDCustomClient: {
			ID:          IDCustomClient,
			DisplayName: "Custom client",
			Kind:        KindCustom,
			// The custom-client bucket spans all three surface types;
			// the inference rule requires evidence of multiple active
			// surface tokens, so the capability list mirrors that.
			Surfaces: []SurfaceCapability{
				{
					Surface: "mcp_http", TokenType: "gateway_bearer",
					AuthMethods: []string{"bearer_token"},
					EventTypes:  []string{"mcp.tool_call"},
					CanBlock:    true, DefaultCoverage: "protected",
				},
				{
					Surface: "http_egress_proxy", TokenType: "proxy_basic",
					AuthMethods: []string{"proxy_token"},
					EventTypes:  []string{"egress.request"},
					CanBlock:    true, DefaultCoverage: "protected",
				},
				{
					Surface: "hooks", TokenType: "hook_bearer",
					AuthMethods: []string{"hook_token"},
					EventTypes:  []string{"hook.event"},
					CanBlock:    true, DefaultCoverage: "protected",
				},
			},
		},
		IDLegacyLoopbackHeader: {
			ID:          IDLegacyLoopbackHeader,
			DisplayName: "Legacy loopback header",
			Kind:        KindLegacy,
			// Loopback header is only honored by the gateway and the
			// forward proxy. Hooks accept anonymous POSTs in local
			// profile, but that is a different code path (no
			// trusted_loopback auth method is recorded).
			Surfaces: []SurfaceCapability{
				{
					Surface: "mcp_http",
					AuthMethods: []string{"trusted_loopback"},
					EventTypes:  []string{"mcp.tool_call"},
					CanBlock:    false, // header-asserted identity, no token
					DefaultCoverage: "observed",
					Caveat:          "loopback header only — issue a gateway_bearer token for stronger auth",
				},
				{
					Surface: "http_egress_proxy",
					AuthMethods: []string{"trusted_loopback"},
					EventTypes:  []string{"egress.request"},
					CanBlock:    false,
					DefaultCoverage: "observed",
					Caveat:          "loopback header only — issue a proxy_basic token for stronger auth",
				},
			},
		},
		IDUnknown: {
			ID:          IDUnknown,
			DisplayName: "Unknown source",
			Kind:        KindUnknown,
			Surfaces:    nil, // explicitly empty: nothing is claimed
		},
	}
}

// orderedIDs returns the connector IDs in the order List should
// surface them. Generic connectors first (one per surface), then
// custom, then legacy, then unknown — that mirrors how the dashboard
// drill-down would group them.
func orderedIDs() []string {
	return []string{
		IDGenericMCPHTTP,
		IDGenericEgressProxy,
		IDGenericHooks,
		IDCustomClient,
		IDLegacyLoopbackHeader,
		IDUnknown,
	}
}
