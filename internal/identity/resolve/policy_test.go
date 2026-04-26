package resolve

import "testing"

// 1. Local default is permissive: no auth required, legacy loopback
// header on, bearer-token type accepted. This is what every existing
// developer setup relies on.
func TestDerivePolicy_LocalDefaultPermissive(t *testing.T) {
	p := DerivePolicy(SurfaceAuthInput{Profile: ProfileLocal})
	if p.RequireAuth {
		t.Error("local default should be permissive (require_auth=false)")
	}
	if !p.ResolverConfig.TrustedLoopbackHeaders {
		t.Error("local default should keep legacy X-Oktsec-Agent path on")
	}
	if len(p.ResolverConfig.AllowedTokenTypes) == 0 {
		t.Error("local default should accept bearer tokens out of the box")
	}
}

// 2. Enterprise default fails closed: auth required, header path off,
// bearer still accepted. Equivalent to what gateway already implemented.
func TestDerivePolicy_EnterpriseDefaultFailClosed(t *testing.T) {
	p := DerivePolicy(SurfaceAuthInput{Profile: ProfileEnterprise})
	if !p.RequireAuth {
		t.Error("enterprise default should require auth")
	}
	if p.ResolverConfig.TrustedLoopbackHeaders {
		t.Error("enterprise must never trust the loopback header")
	}
}

// 3. RequireSurfaceAuth=true forces auth even in local profile. Lets a
// developer test the enterprise contract on a laptop without flipping
// the whole profile.
func TestDerivePolicy_RequireSurfaceAuthForcesAuthInLocal(t *testing.T) {
	p := DerivePolicy(SurfaceAuthInput{
		Profile:            ProfileLocal,
		RequireSurfaceAuth: true,
	})
	if !p.RequireAuth {
		t.Error("require_surface_auth=true must force fail-closed even in local")
	}
}

// 4. Explicit per-surface override wins over both the profile default
// and RequireSurfaceAuth. The override is the operator's last word.
func TestDerivePolicy_ExplicitOverrideWins(t *testing.T) {
	cases := []struct {
		name              string
		profile           Profile
		surfaceAuth       bool
		override          string
		wantRequireAuth   bool
	}{
		// "false" override beats enterprise default.
		{"override-false-beats-enterprise", ProfileEnterprise, false, "false", false},
		// "false" override beats RequireSurfaceAuth.
		{"override-false-beats-require-surface", ProfileLocal, true, "false", false},
		// "true" override forces auth on local.
		{"override-true-on-local", ProfileLocal, false, "true", true},
		// "auto" / unset falls through to profile default.
		{"auto-falls-through", ProfileEnterprise, false, "auto", true},
		{"empty-falls-through", ProfileLocal, false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := DerivePolicy(SurfaceAuthInput{
				Profile:             tc.profile,
				RequireSurfaceAuth:  tc.surfaceAuth,
				RequireAuthOverride: tc.override,
			})
			if p.RequireAuth != tc.wantRequireAuth {
				t.Errorf("RequireAuth = %v, want %v", p.RequireAuth, tc.wantRequireAuth)
			}
		})
	}
}

// 5. Enterprise rejects the loopback header even when AuthMethods
// explicitly lists it. The enterprise floor is non-negotiable.
func TestDerivePolicy_EnterpriseRejectsLoopbackHeaderEvenWhenListed(t *testing.T) {
	p := DerivePolicy(SurfaceAuthInput{
		Profile:                ProfileEnterprise,
		TrustedLoopbackHeaders: true, // YAML opt-in
		AuthMethods:            []string{"bearer_token", "trusted_loopback_header"},
	})
	if p.ResolverConfig.TrustedLoopbackHeaders {
		t.Error("enterprise must drop loopback header even when AuthMethods lists it")
	}
}

// 6. AuthMethods without bearer_token disables the bearer path. Lets a
// surface restrict identity to mTLS only (in a future PR), or a custom
// adapter that wants only proxy basic tokens.
func TestDerivePolicy_AuthMethodsWithoutBearerDropsBearer(t *testing.T) {
	p := DerivePolicy(SurfaceAuthInput{
		Profile:     ProfileLocal,
		AuthMethods: []string{"mtls"}, // mTLS only, no token types
	})
	if len(p.ResolverConfig.AllowedTokenTypes) != 0 {
		t.Errorf("AllowedTokenTypes = %v, want empty when only mTLS is allowed",
			p.ResolverConfig.AllowedTokenTypes)
	}
}

// 7. AllowedTokenTypes is honored when supplied — the egress proxy will
// pass [TokenTypeProxyBasic] and must not get gateway bearer support.
func TestDerivePolicy_AllowedTokenTypesHonored(t *testing.T) {
	p := DerivePolicy(SurfaceAuthInput{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeProxyBasic},
	})
	if len(p.ResolverConfig.AllowedTokenTypes) != 1 || p.ResolverConfig.AllowedTokenTypes[0] != TokenTypeProxyBasic {
		t.Errorf("AllowedTokenTypes = %v, want [proxy_basic]", p.ResolverConfig.AllowedTokenTypes)
	}
}

// 8. ProfileFromString defaults unknown values to local. Misspelled or
// empty profile values must not silently enable enterprise gates.
func TestProfileFromString(t *testing.T) {
	cases := map[string]Profile{
		"":               ProfileLocal,
		"local":          ProfileLocal,
		"enterprise":     ProfileEnterprise,
		"ENTERPRISE":     ProfileEnterprise,
		"  enterprise  ": ProfileEnterprise,
		"prod":           ProfileLocal, // unknown -> safe default
	}
	for in, want := range cases {
		if got := ProfileFromString(in); got != want {
			t.Errorf("ProfileFromString(%q) = %q, want %q", in, got, want)
		}
	}
}
