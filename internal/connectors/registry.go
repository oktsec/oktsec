package connectors

// BuiltinRegistry is the in-process Registry implementation backed by
// the built-in connector table. It is safe for concurrent reads (the
// underlying map is built once in NewBuiltinRegistry and never
// mutated). Future operator-defined connectors would extend this type
// or live behind a composite registry that consults the built-ins
// first.
type BuiltinRegistry struct {
	items map[string]Connector
}

// NewBuiltinRegistry constructs a fresh registry with every built-in
// connector loaded. Callers that want an isolated registry per test
// should call this directly; the package-level Default() registry is
// shared and safe for production use.
func NewBuiltinRegistry() *BuiltinRegistry {
	return &BuiltinRegistry{items: builtinConnectors()}
}

// Get returns the connector with the given ID. The bool is false when
// the ID is not registered; callers should treat that as IDUnknown
// rather than panicking. Returned Connector is a deep copy so callers
// cannot mutate the registry's authoritative state through the
// returned slices.
func (r *BuiltinRegistry) Get(id string) (Connector, bool) {
	c, ok := r.items[id]
	if !ok {
		return Connector{}, false
	}
	return cloneConnector(c), true
}

// List returns every registered connector in a deterministic order so
// dashboard rendering does not flicker between requests. Each returned
// Connector is a deep copy.
func (r *BuiltinRegistry) List() []Connector {
	out := make([]Connector, 0, len(r.items))
	for _, id := range orderedIDs() {
		if c, ok := r.items[id]; ok {
			out = append(out, cloneConnector(c))
		}
	}
	return out
}

// surfaceTokenTypes is the canonical priority order for surface tokens
// the inference rule cares about. Defined in one place so the count /
// last-active loop and the single-token branches always agree.
var surfaceTokenTypes = []string{"gateway_bearer", "proxy_basic", "hook_bearer"}

// Infer chooses the connector that best matches the evidence at hand.
//
// Rules (mirrors the Phase 2B.1 spec table):
//
//   - 2+ active surface tokens                  -> custom-client
//   - exactly 1 active gateway_bearer token     -> generic-mcp-http
//   - exactly 1 active proxy_basic token        -> generic-egress-proxy
//   - exactly 1 active hook_bearer token        -> generic-hooks
//   - 0 active tokens, trusted_loopback in evidence -> legacy-loopback-header
//   - 0 active tokens, no loopback evidence     -> unknown
//
// Both maps may be nil; callers must not pass entries for revoked or
// expired tokens (the coverage layer is responsible for that filter).
// observedAuthMethods is intentionally generic so future surfaces can
// contribute their own evidence (e.g. wrapper-signed activity) without
// changing the signature.
func (r *BuiltinRegistry) Infer(activeTokenTypes, observedAuthMethods map[string]bool) Connector {
	activeCount := 0
	var lastActive string
	for _, t := range surfaceTokenTypes {
		if activeTokenTypes[t] {
			activeCount++
			lastActive = t
		}
	}
	var picked string
	switch {
	case activeCount >= 2:
		picked = IDCustomClient
	case lastActive == "gateway_bearer":
		picked = IDGenericMCPHTTP
	case lastActive == "proxy_basic":
		picked = IDGenericEgressProxy
	case lastActive == "hook_bearer":
		picked = IDGenericHooks
	case observedAuthMethods["trusted_loopback"]:
		picked = IDLegacyLoopbackHeader
	default:
		picked = IDUnknown
	}
	return cloneConnector(r.items[picked])
}

// cloneConnector returns a deep copy of c so callers cannot mutate the
// registry's authoritative state via the returned slices. Surfaces
// gets a fresh slice; each SurfaceCapability inside gets its own
// AuthMethods and EventTypes copies. Strings are immutable in Go so
// they can be assigned by value safely.
func cloneConnector(c Connector) Connector {
	out := c
	if c.Surfaces != nil {
		out.Surfaces = make([]SurfaceCapability, len(c.Surfaces))
		for i, s := range c.Surfaces {
			cp := s
			if s.AuthMethods != nil {
				cp.AuthMethods = append([]string(nil), s.AuthMethods...)
			}
			if s.EventTypes != nil {
				cp.EventTypes = append([]string(nil), s.EventTypes...)
			}
			out.Surfaces[i] = cp
		}
	}
	return out
}

// defaultRegistry is the process-wide registry used by Default(). It
// is built once at package init and never mutated, so it is safe for
// concurrent use.
var defaultRegistry = NewBuiltinRegistry()

// Default returns the process-wide built-in registry. Callers that
// need to inject a different registry (e.g., tests with a custom
// connector) should accept a Registry parameter and let the operator
// choose; Default is the convenience for the common path.
func Default() Registry { return defaultRegistry }
