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

// Hook stage names. The hooks handler normalizes incoming wire
// values (e.g., Claude Code's "PreToolUse") into these snake_case
// forms before emitting activity, so the coverage helper compares
// against a single canonical vocabulary.
const (
	HookEventPreToolUse  = "pre_tool_use"
	HookEventPostToolUse = "post_tool_use"
)

// CoverageFromHookEvent returns the coverage label and confidence the
// dashboard should attribute to a single hook event. It is
// stage-driven on purpose: only pre_tool_use can claim Protected
// because it is the only stage where oktsec can block before the
// action runs. Every other stage is evidence after-the-fact at best,
// regardless of how trustworthy the auth method is.
//
//   - pre_tool_use inherits the auth-method base — token auth is
//     Protected/100, trusted_loopback is Observed/80, etc.
//   - post_tool_use with a token-authenticated source is Observed/60
//     per the Phase 2B.1 spec ladder. Unauthenticated falls through
//     to the auth-method base.
//   - Any other explicit stage (notification, session lifecycle
//     events, future stages) and any unrecognized stage value cannot
//     be Protected. With a token-authenticated source we record
//     Observed/40 — the source is trustworthy but we cannot say which
//     lifecycle moment this evidence represents. Without a token we
//     fall through to the auth-method base.
//
// The conservative default for unknown stages is the point of this
// helper: a future hook stage added to a client must not silently
// inflate the coverage matrix.
func CoverageFromHookEvent(authMethod, hookEvent string) (CoverageMode, int) {
	base := CoverageFromAuthMethod(authMethod)
	conf := ConfidenceFromAuthMethod(authMethod)
	switch hookEvent {
	case HookEventPreToolUse:
		return base, conf
	case HookEventPostToolUse:
		if base == CoverageProtected {
			return CoverageObserved, 60
		}
		return base, conf
	default:
		if base == CoverageProtected {
			return CoverageObserved, 40
		}
		return base, conf
	}
}
