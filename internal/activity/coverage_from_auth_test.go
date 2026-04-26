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
