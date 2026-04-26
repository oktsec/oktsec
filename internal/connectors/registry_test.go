package connectors

import (
	"reflect"
	"testing"
)

// The Phase 2B.1 spec table is reproduced here as a single source of
// truth: every row in the spec corresponds to one row in this table.
// A failure here means the wire-level connector inference would drift
// from the documented matrix.
func TestBuiltinRegistry_Infer(t *testing.T) {
	r := NewBuiltinRegistry()

	cases := []struct {
		name     string
		active   map[string]bool
		observed map[string]bool
		wantID   string
	}{
		{
			name:   "single gateway_bearer maps to generic-mcp-http",
			active: map[string]bool{"gateway_bearer": true},
			wantID: IDGenericMCPHTTP,
		},
		{
			name:   "single proxy_basic maps to generic-egress-proxy",
			active: map[string]bool{"proxy_basic": true},
			wantID: IDGenericEgressProxy,
		},
		{
			name:   "single hook_bearer maps to generic-hooks",
			active: map[string]bool{"hook_bearer": true},
			wantID: IDGenericHooks,
		},
		{
			name:   "two surface tokens map to custom-client",
			active: map[string]bool{"gateway_bearer": true, "proxy_basic": true},
			wantID: IDCustomClient,
		},
		{
			name:   "three surface tokens map to custom-client",
			active: map[string]bool{"gateway_bearer": true, "proxy_basic": true, "hook_bearer": true},
			wantID: IDCustomClient,
		},
		{
			// The coverage layer filters revoked/expired before
			// calling Infer, so an empty active map represents that
			// real-world case. With loopback evidence present, the
			// principal is labeled legacy-loopback-header.
			name:     "no active tokens with loopback evidence maps to legacy-loopback-header",
			active:   map[string]bool{},
			observed: map[string]bool{"trusted_loopback": true},
			wantID:   IDLegacyLoopbackHeader,
		},
		{
			// No tokens, no loopback evidence (e.g. enterprise profile
			// where the loopback header is rejected). The current-state
			// label is unknown — the principal exists in config but
			// has no working auth path on any surface.
			name:     "no active tokens and no observed evidence maps to unknown",
			active:   map[string]bool{},
			observed: map[string]bool{},
			wantID:   IDUnknown,
		},
		{
			name:   "nil maps are treated as empty (no panic)",
			active: nil, observed: nil,
			wantID: IDUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.Infer(tc.active, tc.observed)
			if got.ID != tc.wantID {
				t.Errorf("connector = %q; want %q", got.ID, tc.wantID)
			}
		})
	}
}

// Get returns the registered connector and false for unknown IDs.
// Tests rely on this contract to avoid panicking on a typo or a
// connector that has not been registered yet.
func TestBuiltinRegistry_Get(t *testing.T) {
	r := NewBuiltinRegistry()

	if c, ok := r.Get(IDGenericMCPHTTP); !ok || c.DisplayName != "Generic MCP HTTP" {
		t.Errorf("Get(generic-mcp-http) = (%+v, %v); want hit", c, ok)
	}
	if _, ok := r.Get("nope-this-id-does-not-exist"); ok {
		t.Error("Get(nope) returned ok=true; want false")
	}
}

// List returns every built-in in a deterministic order. Dashboard
// rendering pivots on this order so flicker between requests would
// appear as a regression in the table.
func TestBuiltinRegistry_ListIsStable(t *testing.T) {
	r := NewBuiltinRegistry()
	first := r.List()
	second := r.List()

	if !reflect.DeepEqual(first, second) {
		t.Errorf("List order is not stable across calls")
	}
	wantIDs := []string{
		IDGenericMCPHTTP, IDGenericEgressProxy, IDGenericHooks,
		IDCustomClient, IDLegacyLoopbackHeader, IDUnknown,
	}
	if len(first) != len(wantIDs) {
		t.Fatalf("List length = %d; want %d", len(first), len(wantIDs))
	}
	for i, id := range wantIDs {
		if first[i].ID != id {
			t.Errorf("List[%d].ID = %q; want %q", i, first[i].ID, id)
		}
	}
}

// Custom-client built-in covers all three surface types. This is the
// invariant that lets the dashboard show "Custom client" without
// branching on a specific surface.
func TestBuiltinRegistry_CustomClientCoversAllSurfaces(t *testing.T) {
	r := NewBuiltinRegistry()
	cc, ok := r.Get(IDCustomClient)
	if !ok {
		t.Fatal("custom-client connector not registered")
	}
	want := map[string]bool{"mcp_http": false, "http_egress_proxy": false, "hooks": false}
	for _, s := range cc.Surfaces {
		if _, expected := want[s.Surface]; expected {
			want[s.Surface] = true
		}
	}
	for surface, found := range want {
		if !found {
			t.Errorf("custom-client missing surface %q", surface)
		}
	}
}

// Default returns a non-nil registry. The tests would catch a nil
// dereference even without this assertion; the explicit check keeps
// the contract obvious for new readers.
func TestDefault_NotNil(t *testing.T) {
	if Default() == nil {
		t.Fatal("Default registry is nil")
	}
}

// Mutating a connector returned from Get / List / Infer must not
// affect later calls. The registry must hand back deep copies so a
// caller that scribbles on Surfaces / AuthMethods / EventTypes
// cannot poison Default() for the next dashboard request.
func TestBuiltinRegistry_ReturnedConnectorsAreImmutable(t *testing.T) {
	r := NewBuiltinRegistry()

	first, ok := r.Get(IDGenericMCPHTTP)
	if !ok {
		t.Fatal("generic-mcp-http not registered")
	}
	if len(first.Surfaces) == 0 || len(first.Surfaces[0].AuthMethods) == 0 {
		t.Fatal("test fixture: generic-mcp-http has no surfaces or auth methods")
	}

	// Scribble on the returned slices.
	first.Surfaces[0].AuthMethods[0] = "POISONED"
	first.Surfaces[0].EventTypes[0] = "POISONED"
	first.Surfaces[0].Surface = "POISONED"

	// A fresh Get must see the original values.
	second, _ := r.Get(IDGenericMCPHTTP)
	if got := second.Surfaces[0].AuthMethods[0]; got == "POISONED" {
		t.Errorf("AuthMethods[0] mutation leaked back into the registry: got %q", got)
	}
	if got := second.Surfaces[0].EventTypes[0]; got == "POISONED" {
		t.Errorf("EventTypes[0] mutation leaked back into the registry: got %q", got)
	}
	if got := second.Surfaces[0].Surface; got == "POISONED" {
		t.Errorf("Surface mutation leaked back into the registry: got %q", got)
	}

	// Same contract via List and Infer.
	for _, c := range r.List() {
		if c.ID == IDGenericMCPHTTP {
			if c.Surfaces[0].AuthMethods[0] == "POISONED" {
				t.Error("List returned a poisoned connector")
			}
		}
	}
	inferred := r.Infer(map[string]bool{"gateway_bearer": true}, nil)
	if inferred.Surfaces[0].AuthMethods[0] == "POISONED" {
		t.Error("Infer returned a poisoned connector")
	}
}
