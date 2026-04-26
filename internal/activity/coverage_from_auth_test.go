package activity

import "testing"

// CoverageFromHookEvent encodes the Phase 2B.1 invariant that
// "Protected means oktsec can block before the action ran." A failing
// row here means the dashboard would over-claim coverage on at least
// one cell, so the table is exhaustive on purpose.
func TestCoverageFromHookEvent(t *testing.T) {
	cases := []struct {
		name       string
		authMethod string
		hookEvent  string
		wantCov    CoverageMode
		wantConf   int
	}{
		{
			name:       "pre_tool_use with hook_token is protected",
			authMethod: "hook_token",
			hookEvent:  "pre_tool_use",
			wantCov:    CoverageProtected,
			wantConf:   100,
		},
		{
			name:       "post_tool_use with hook_token downgrades to observed/60",
			authMethod: "hook_token",
			hookEvent:  "post_tool_use",
			wantCov:    CoverageObserved,
			wantConf:   60,
		},
		{
			name:       "post_tool_use with bearer_token also downgrades (any token-protected auth)",
			authMethod: "bearer_token",
			hookEvent:  "post_tool_use",
			wantCov:    CoverageObserved,
			wantConf:   60,
		},
		{
			name:       "pre_tool_use unauthenticated stays observed/0",
			authMethod: "",
			hookEvent:  "pre_tool_use",
			wantCov:    CoverageObserved,
			wantConf:   0,
		},
		{
			name:       "post_tool_use unauthenticated stays observed/0 (no inflation either way)",
			authMethod: "",
			hookEvent:  "post_tool_use",
			wantCov:    CoverageObserved,
			wantConf:   0,
		},
		{
			name:       "trusted_loopback is unaffected by stage (cannot block; already observed)",
			authMethod: "trusted_loopback",
			hookEvent:  "post_tool_use",
			wantCov:    CoverageObserved,
			wantConf:   80,
		},
		{
			// Claude Code emits Notification/Stop/SessionStart hooks
			// in addition to PreToolUse/PostToolUse. None of them
			// run before the action, so token auth must not promote
			// them to Protected.
			name:       "notification with hook_token is observed/40 (cannot block, unknown stage)",
			authMethod: "hook_token",
			hookEvent:  "notification",
			wantCov:    CoverageObserved,
			wantConf:   40,
		},
		{
			name:       "stop with hook_token is observed/40 (session lifecycle, cannot block)",
			authMethod: "hook_token",
			hookEvent:  "stop",
			wantCov:    CoverageObserved,
			wantConf:   40,
		},
		{
			// Defensive: a future client could send a stage name we
			// have not seen. The conservative default protects the
			// matrix from silent inflation.
			name:       "unknown stage with hook_token is observed/40",
			authMethod: "hook_token",
			hookEvent:  "future_stage_we_dont_know",
			wantCov:    CoverageObserved,
			wantConf:   40,
		},
		{
			// Defensive: empty stage should never happen post-normalization,
			// but if it does the helper must not over-claim.
			name:       "empty stage with hook_token is observed/40 (defensive)",
			authMethod: "hook_token",
			hookEvent:  "",
			wantCov:    CoverageObserved,
			wantConf:   40,
		},
		{
			name:       "notification unauthenticated stays observed/0 (no inflation)",
			authMethod: "",
			hookEvent:  "notification",
			wantCov:    CoverageObserved,
			wantConf:   0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCov, gotConf := CoverageFromHookEvent(tc.authMethod, tc.hookEvent)
			if gotCov != tc.wantCov {
				t.Errorf("coverage = %q; want %q", gotCov, tc.wantCov)
			}
			if gotConf != tc.wantConf {
				t.Errorf("confidence = %d; want %d", gotConf, tc.wantConf)
			}
		})
	}
}
