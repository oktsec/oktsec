package activity

// CoverageFromAuthMethod maps an auth method id (the string form of
// resolve.AuthMethod) to the dashboard coverage label a single observed
// event should carry. Token-based and cryptographic auth produce
// Protected. Trusted local (loopback header), unauthenticated
// telemetry, or anything unrecognized produce Observed — under-claim
// rather than over-claim.
//
// Surface adapters (gateway, forward proxy, hooks) all call this so the
// dashboard cannot drift from a per-surface fork of the same logic.
func CoverageFromAuthMethod(method string) CoverageMode {
	switch method {
	case "bearer_token", "proxy_token", "hook_token",
		"ed25519", "mtls", "wrapper":
		return CoverageProtected
	case "trusted_loopback":
		return CoverageObserved
	}
	return CoverageObserved
}

// ConfidenceFromAuthMethod maps an auth method id to the dashboard
// confidence hint. Numbers come from the Phase 2B.1 spec:
//
//	100  token-authenticated direct surface evidence (bearer / proxy /
//	     hook tokens, ed25519, mTLS, wrapper-signed)
//	 80  trusted local loopback evidence
//	  0  unknown or anonymous; surfaced separately as diagnostic-quality
//
// Confidence is a hint for the dashboard, not a policy input.
func ConfidenceFromAuthMethod(method string) int {
	switch method {
	case "bearer_token", "proxy_token", "hook_token",
		"ed25519", "mtls", "wrapper":
		return 100
	case "trusted_loopback":
		return 80
	}
	return 0
}

// HookEventPostToolUse is the normalized stage name for hooks that
// fire after the tool ran. Kept as a constant so the coverage helper
// and any future hook-stage logic agree on the wire value.
const HookEventPostToolUse = "post_tool_use"

// CoverageFromHookEvent returns the coverage label and confidence the
// dashboard should attribute to a single hook event. It accounts for
// the hook stage, which CoverageFromAuthMethod alone cannot:
//
//   - pre_tool_use is the only stage where oktsec can block before the
//     action ran; with token auth it is genuinely Protected/100.
//   - post_tool_use is evidence after the fact. Even when carried by a
//     valid hook_token the surface cannot block, so it is Observed
//     with confidence 60 per the Phase 2B.1 spec ladder.
//
// Unauthenticated hooks (any stage) inherit the auth-method-only
// mapping — they were already Observed with low confidence and the
// stage does not change that.
func CoverageFromHookEvent(authMethod, hookEvent string) (CoverageMode, int) {
	base := CoverageFromAuthMethod(authMethod)
	conf := ConfidenceFromAuthMethod(authMethod)
	if hookEvent == HookEventPostToolUse && base == CoverageProtected {
		return CoverageObserved, 60
	}
	return base, conf
}
