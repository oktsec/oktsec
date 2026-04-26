package resolve

import "strings"

// ProfileFromString maps the on-disk `deployment.profile` value to a
// resolve.Profile. Empty/unrecognized values default to ProfileLocal so a
// missing config field never accidentally enables enterprise fail-closed
// gates without an explicit opt-in.
func ProfileFromString(s string) Profile {
	if strings.EqualFold(strings.TrimSpace(s), "enterprise") {
		return ProfileEnterprise
	}
	return ProfileLocal
}

// SurfaceAuthInput is the minimal projection of cfg every surface adapter
// needs to derive its identity policy. Adapters build this from their own
// section of cfg (cfg.Gateway, cfg.ForwardProxy, cfg.Hooks, ...) so the
// helper does not have to know about every surface struct in config.
//
// All fields are optional. The zero value yields a permissive local
// policy with bearer-token auth and the legacy loopback header on.
type SurfaceAuthInput struct {
	// Surface identifies which boundary this policy applies to. Used when
	// the resolver needs to disambiguate token types or carries it into
	// activity events.
	Surface Surface

	// Profile is the deployment profile (local or enterprise). Use
	// ProfileFromString(cfg.Deployment.Profile) at the call site.
	Profile Profile

	// RequireSurfaceAuth comes from cfg.Deployment.RequireSurfaceAuth and
	// forces fail-closed on every surface even in local profile. Lets a
	// developer test the enterprise contract without flipping the whole
	// profile.
	RequireSurfaceAuth bool

	// RequireAuthOverride is the per-surface knob ("auto" | "true" |
	// "false"). It wins over the profile/RequireSurfaceAuth defaults.
	// Empty string is treated as "auto".
	RequireAuthOverride string

	// AuthMethods is the per-surface allow-list. Empty means "use the
	// profile default" (bearer + loopback header in local; bearer + mTLS
	// in enterprise). Recognized values: bearer_token, mtls,
	// trusted_loopback_header, proxy_basic_token, hook_token.
	AuthMethods []string

	// TrustedLoopbackHeaders is the surface's opt-in for the legacy
	// X-Oktsec-Agent path. Honored only in local profile; enterprise
	// always treats the header as reported-actor metadata.
	TrustedLoopbackHeaders bool

	// LoopbackHeaderName overrides the default header name used for the
	// trusted-loopback path. Empty defaults to "X-Oktsec-Agent".
	LoopbackHeaderName string

	// ReportedActorHeaderName, when non-empty, declares a header whose
	// value populates ReportedActor (never Principal).
	ReportedActorHeaderName string

	// ReportedActorPayloadKeys lists payload field names whose values may
	// surface as ReportedActor. First non-empty wins.
	ReportedActorPayloadKeys []string

	// AllowedTokenTypes restricts which TokenTypes the resolver tries.
	// The gateway uses [GatewayBearer], the egress proxy [ProxyBasic],
	// hooks [HookBearer]. Empty falls back to [GatewayBearer] which is
	// the historically-default surface.
	AllowedTokenTypes []TokenType
}

// SurfacePolicy is the resolved per-surface identity contract: which
// resolver Config to pass to Resolve, and whether the surface adapter
// must short-circuit unauthenticated requests with a fail-closed
// response (HTTP 401, JSON-RPC error, etc.).
type SurfacePolicy struct {
	Profile        Profile
	RequireAuth    bool
	ResolverConfig Config
}

// DerivePolicy folds the inputs into a SurfacePolicy. The same function
// serves the gateway, the forward proxy, hooks, and the agent message
// API; surface adapters just supply their own SurfaceAuthInput.
//
// Precedence for RequireAuth (highest first):
//  1. Explicit RequireAuthOverride ("true" / "false").
//  2. RequireSurfaceAuth=true (developer test of enterprise contract).
//  3. Enterprise profile.
//  4. Otherwise: false (permissive local default).
//
// Loopback-header rules:
//   - Enterprise profile NEVER trusts the loopback header, regardless of
//     TrustedLoopbackHeaders or what AuthMethods lists. The header always
//     surfaces as reported-actor metadata only.
//   - Local profile honors TrustedLoopbackHeaders (or, when AuthMethods
//     is empty, defaults it on so existing local setups keep working).
func DerivePolicy(in SurfaceAuthInput) SurfacePolicy {
	profile := in.Profile
	if profile == "" {
		profile = ProfileLocal
	}

	loopbackHeaders := in.TrustedLoopbackHeaders
	// In local profile, an empty AuthMethods list keeps the legacy
	// X-Oktsec-Agent path on so existing setups do not break silently.
	if profile == ProfileLocal && len(in.AuthMethods) == 0 {
		loopbackHeaders = true
	}
	// AuthMethods may explicitly enable the loopback header.
	for _, m := range in.AuthMethods {
		if strings.EqualFold(strings.TrimSpace(m), "trusted_loopback_header") {
			loopbackHeaders = true
		}
	}
	// Enterprise floor: header never authenticates.
	if profile == ProfileEnterprise {
		loopbackHeaders = false
	}

	allowed := in.AllowedTokenTypes
	if len(allowed) == 0 {
		allowed = []TokenType{TokenTypeGatewayBearer}
	}
	// If the surface declared an explicit AuthMethods list and bearer is
	// missing, drop bearer support. mTLS is kept as a no-op for now (no
	// cert resolution wired) so a future enterprise switch is purely
	// config-driven.
	if len(in.AuthMethods) > 0 {
		hasBearer := false
		for _, m := range in.AuthMethods {
			switch strings.ToLower(strings.TrimSpace(m)) {
			case "bearer_token", "proxy_basic_token", "hook_token":
				hasBearer = true
			}
		}
		if !hasBearer {
			allowed = nil
		}
	}

	loopbackName := in.LoopbackHeaderName
	if loopbackName == "" {
		loopbackName = "X-Oktsec-Agent"
	}

	return SurfacePolicy{
		Profile:     profile,
		RequireAuth: deriveRequireAuth(in, profile),
		ResolverConfig: Config{
			Profile:                  profile,
			AllowedTokenTypes:        allowed,
			TrustedLoopbackHeaders:   loopbackHeaders,
			LoopbackHeaderName:       loopbackName,
			ReportedActorHeaderName:  in.ReportedActorHeaderName,
			ReportedActorPayloadKeys: in.ReportedActorPayloadKeys,
		},
	}
}

func deriveRequireAuth(in SurfaceAuthInput, profile Profile) bool {
	switch strings.ToLower(strings.TrimSpace(in.RequireAuthOverride)) {
	case "true", "yes", "1":
		return true
	case "false", "no", "0":
		return false
	}
	if in.RequireSurfaceAuth {
		return true
	}
	return profile == ProfileEnterprise
}
