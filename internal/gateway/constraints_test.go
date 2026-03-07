package gateway

import (
	"testing"
	"time"
)

func TestConstraintChecker_NoConstraints(t *testing.T) {
	cc := NewConstraintChecker(nil, nil)
	r := cc.CheckToolCall("agent-a", "read_file", map[string]string{"path": "/data/file.txt"})
	if !r.Allowed {
		t.Fatalf("no constraints should allow: %s", r.Reason)
	}
}

func TestConstraintChecker_AllowedPattern(t *testing.T) {
	cc := NewConstraintChecker(
		map[string][]ToolConstraint{
			"agent-a": {{
				Tool: "read_file",
				Parameters: map[string]ParamConstraint{
					"path": {AllowedPatterns: []string{"/data/*", "/public/*"}},
				},
			}},
		}, nil,
	)

	// Allowed
	r := cc.CheckToolCall("agent-a", "read_file", map[string]string{"path": "/data/report.csv"})
	if !r.Allowed {
		t.Fatalf("should match allowed pattern: %s", r.Reason)
	}

	// Blocked — not in allowed patterns
	r = cc.CheckToolCall("agent-a", "read_file", map[string]string{"path": "/secrets/key.pem"})
	if r.Allowed {
		t.Fatal("should reject path not matching allowed patterns")
	}
}

func TestConstraintChecker_BlockedPattern(t *testing.T) {
	cc := NewConstraintChecker(
		map[string][]ToolConstraint{
			"agent-a": {{
				Tool: "read_file",
				Parameters: map[string]ParamConstraint{
					"path": {BlockedPatterns: []string{"/secrets/*", "*.env"}},
				},
			}},
		}, nil,
	)

	r := cc.CheckToolCall("agent-a", "read_file", map[string]string{"path": "/secrets/key.pem"})
	if r.Allowed {
		t.Fatal("should block /secrets/* pattern")
	}

	r = cc.CheckToolCall("agent-a", "read_file", map[string]string{"path": "/data/report.csv"})
	if !r.Allowed {
		t.Fatalf("should allow non-blocked path: %s", r.Reason)
	}
}

func TestConstraintChecker_MaxLength(t *testing.T) {
	cc := NewConstraintChecker(
		map[string][]ToolConstraint{
			"agent-a": {{
				Tool: "write_file",
				Parameters: map[string]ParamConstraint{
					"content": {MaxLength: 100},
				},
			}},
		}, nil,
	)

	r := cc.CheckToolCall("agent-a", "write_file", map[string]string{"content": "short"})
	if !r.Allowed {
		t.Fatalf("short content should be allowed: %s", r.Reason)
	}

	long := make([]byte, 150)
	for i := range long {
		long[i] = 'x'
	}
	r = cc.CheckToolCall("agent-a", "write_file", map[string]string{"content": string(long)})
	if r.Allowed {
		t.Fatal("content exceeding max_length should be blocked")
	}
}

func TestConstraintChecker_Cooldown(t *testing.T) {
	cc := NewConstraintChecker(
		map[string][]ToolConstraint{
			"agent-a": {{
				Tool:         "write_file",
				CooldownSecs: 2,
			}},
		}, nil,
	)

	// First call — allowed
	r := cc.CheckToolCall("agent-a", "write_file", nil)
	if !r.Allowed {
		t.Fatalf("first call should be allowed: %s", r.Reason)
	}
	cc.RecordToolCall("agent-a", "write_file")

	// Immediate second call — should be on cooldown
	r = cc.CheckToolCall("agent-a", "write_file", nil)
	if r.Allowed {
		t.Fatal("immediate second call should be on cooldown")
	}

	// Different tool — not on cooldown
	r = cc.CheckToolCall("agent-a", "read_file", nil)
	if !r.Allowed {
		t.Fatalf("different tool should not be on cooldown: %s", r.Reason)
	}
}

func TestConstraintChecker_ChainRule(t *testing.T) {
	cc := NewConstraintChecker(
		nil,
		map[string][]ToolChainRule{
			"agent-a": {{
				If:           "get_credentials",
				Then:         []string{"send_email", "http_request"},
				CooldownSecs: 2,
			}},
		},
	)

	// Call get_credentials
	r := cc.CheckToolCall("agent-a", "get_credentials", nil)
	if !r.Allowed {
		t.Fatalf("get_credentials should be allowed: %s", r.Reason)
	}
	cc.RecordToolCall("agent-a", "get_credentials")

	// send_email should now be blocked
	r = cc.CheckToolCall("agent-a", "send_email", nil)
	if r.Allowed {
		t.Fatal("send_email should be blocked by chain rule")
	}

	// http_request should also be blocked
	r = cc.CheckToolCall("agent-a", "http_request", nil)
	if r.Allowed {
		t.Fatal("http_request should be blocked by chain rule")
	}

	// Unrelated tool should be fine
	r = cc.CheckToolCall("agent-a", "read_file", nil)
	if !r.Allowed {
		t.Fatalf("read_file should not be affected by chain rule: %s", r.Reason)
	}

	// Wait for cooldown to expire
	time.Sleep(2100 * time.Millisecond)
	r = cc.CheckToolCall("agent-a", "send_email", nil)
	if !r.Allowed {
		t.Fatalf("send_email should be allowed after cooldown: %s", r.Reason)
	}
}

func TestConstraintChecker_DifferentAgents(t *testing.T) {
	cc := NewConstraintChecker(
		map[string][]ToolConstraint{
			"agent-a": {{
				Tool:         "write_file",
				CooldownSecs: 60,
			}},
		}, nil,
	)

	cc.RecordToolCall("agent-a", "write_file")

	// agent-b should not be affected
	r := cc.CheckToolCall("agent-b", "write_file", nil)
	if !r.Allowed {
		t.Fatalf("agent-b should not share cooldown with agent-a: %s", r.Reason)
	}
}

func TestCheckParamConstraint_AllowedAndBlocked(t *testing.T) {
	pc := ParamConstraint{
		AllowedPatterns: []string{"/data/*"},
		BlockedPatterns: []string{"/data/secret*"},
	}

	// Allowed
	r := checkParamConstraint("path", "/data/report.csv", pc)
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}

	// Blocked takes precedence
	r = checkParamConstraint("path", "/data/secret.key", pc)
	if r.Allowed {
		t.Fatal("blocked pattern should take precedence over allowed")
	}
}
