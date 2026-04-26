package coverage

import "testing"

// LimitationShortLabel must only ever return a value in
// AllowedShortLabels or the empty string. Long copy in a table cell
// breaks the matrix layout (paragraph wrap, row-height instability)
// and the drill-down drawer is the right place for full sentences.
// This test pins the contract so a future "add one more case" cannot
// silently widen the set without updating AllowedShortLabels.
func TestLimitationShortLabel_OnlyReturnsAllowedSet(t *testing.T) {
	allowed := map[string]bool{}
	for _, s := range AllowedShortLabels {
		allowed[s] = true
	}

	cases := []struct {
		name string
		lim  string
		want string
	}{
		{"empty limitation -> empty", "", ""},
		{"gateway not enabled -> Surface off", "gateway not enabled", "Surface off"},
		{"forward proxy not enabled -> Surface off", "forward proxy not enabled", "Surface off"},
		{"hooks gateway disabled -> Surface off", "hooks endpoint not exposed (gateway disabled)", "Surface off"},
		{"loopback caveat -> Loopback only", "loopback header only — issue a gateway_bearer token for stronger auth", "Loopback only"},
		{"no gateway token -> No token", "no gateway_bearer token configured", "No token"},
		{"no proxy token -> No token", "no proxy_basic token configured", "No token"},
		{"hooks no token, surface requires auth -> No token", "no hook_bearer token; surface requires authenticated identity", "No token"},
		{"hooks unauth telemetry -> Telemetry only", "no hook_bearer token; events accepted as observed telemetry only", "Telemetry only"},
		{"hooks pre-action -> Pre-action only", "pre-action hooks block when client honors the decision; post-action hooks are observed only", "Pre-action only"},
		{"egress domain-only -> Domain only", "domain-only (HTTPS CONNECT and disabled body scanning)", "Domain only"},

		// The previously-emitted long labels for protected egress with
		// HTTPS body inspection have no scannable short form, so the
		// cell shows nothing inline. The drawer carries the full text.
		{"plain HTTP body inspection -> empty", "plain HTTP bodies inspected; HTTPS CONNECT is domain-only unless inspection is enabled", ""},
		{"request body inspection only -> empty", "request bodies inspected on plain HTTP; HTTPS CONNECT is domain-only", ""},

		// Defensive: an unrecognized limitation produces no inline
		// label so the cell never grows a paragraph.
		{"unknown wording -> empty", "some future limitation we have not seen", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LimitationShortLabel(CoverageCell{Limitation: tc.lim})
			if got != tc.want {
				t.Errorf("LimitationShortLabel(%q) = %q; want %q", tc.lim, got, tc.want)
			}
			// Closed-set invariant: every non-empty return must be
			// in AllowedShortLabels. A future addition has to update
			// both the function and the catalog.
			if got != "" && !allowed[got] {
				t.Errorf("LimitationShortLabel(%q) returned %q which is not in AllowedShortLabels %v",
					tc.lim, got, AllowedShortLabels)
			}
		})
	}
}
