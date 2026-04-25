package policy

import (
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

func TestCheckACL_NoAgents(t *testing.T) {
	e := NewEvaluator(&config.Config{})
	d := e.CheckACL("anyone", "anyone-else")
	if !d.Allowed {
		t.Error("should allow when no agents configured")
	}
}

func TestCheckACL_Allowed(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {CanMessage: []string{"b", "c"}},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "b")
	if !d.Allowed {
		t.Error("a should be allowed to message b")
	}
}

func TestCheckACL_Denied(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {CanMessage: []string{"b"}},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "c")
	if d.Allowed {
		t.Error("a should not be allowed to message c")
	}
}

func TestCheckACL_Wildcard(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"admin": {CanMessage: []string{"*"}},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("admin", "anyone")
	if !d.Allowed {
		t.Error("wildcard should allow messaging anyone")
	}
}

func TestCheckACL_UnknownSender(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {CanMessage: []string{"b"}},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("unknown", "b")
	if !d.Allowed {
		t.Error("unknown sender should be allowed (not in policy)")
	}
}

func TestCheckACL_NoRestrictions(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {CanMessage: nil},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "anyone")
	if !d.Allowed {
		t.Error("agent with no can_message should be allowed to message anyone")
	}
}

func TestCheckACL_DefaultDeny_UnknownSender(t *testing.T) {
	cfg := &config.Config{
		DefaultPolicy: "deny",
		Agents: map[string]config.Agent{
			"a": {CanMessage: []string{"b"}},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("unknown", "b")
	if d.Allowed {
		t.Error("unknown sender should be denied when default_policy is deny")
	}
}

func TestCheckACL_DefaultDeny_EmptyAgents(t *testing.T) {
	cfg := &config.Config{
		DefaultPolicy: "deny",
		Agents:        map[string]config.Agent{},
	}
	e := NewEvaluator(cfg)

	// Empty agents map still allows (no ACL configured) — deny only for unknown senders when agents exist
	d := e.CheckACL("anyone", "other")
	if !d.Allowed {
		t.Error("empty agents map should allow all (no ACL configured)")
	}
}

func TestCheckACL_ACLEntries_Allowed(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {
				ACLEntries: []config.ACLEntryConfig{
					{Target: "b"},
				},
			},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "b")
	if !d.Allowed {
		t.Errorf("a should be allowed to message b via ACL entry: %s", d.Reason)
	}
}

func TestCheckACL_ACLEntries_Denied(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {
				ACLEntries: []config.ACLEntryConfig{
					{Target: "b"},
				},
			},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "c")
	if d.Allowed {
		t.Error("a should not be allowed to message c (not in ACL entries)")
	}
}

func TestCheckACL_ACLEntries_RateConstraint(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {
				ACLEntries: []config.ACLEntryConfig{
					{
						Target: "b",
						Constraints: []config.ACLConstraint{
							{Type: "rate", MaxMessages: 2, WindowSecs: 60},
						},
					},
				},
			},
		},
	}
	e := NewEvaluator(cfg)

	for i := 0; i < 2; i++ {
		d := e.CheckACL("a", "b")
		if !d.Allowed {
			t.Fatalf("message %d should be allowed: %s", i+1, d.Reason)
		}
	}

	d := e.CheckACL("a", "b")
	if d.Allowed {
		t.Error("3rd message should be rate limited")
	}
}

func TestCheckACL_ACLEntries_TTLExpired(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {
				ACLEntries: []config.ACLEntryConfig{
					{
						Target: "b",
						Constraints: []config.ACLConstraint{
							{Type: "ttl", ExpiresAt: "2020-01-01T00:00:00Z"},
						},
					},
				},
			},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "b")
	if d.Allowed {
		t.Error("expired TTL should deny the message")
	}
}

func TestCheckACL_ACLEntries_WildcardTarget(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"admin": {
				ACLEntries: []config.ACLEntryConfig{
					{Target: "*"},
				},
			},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("admin", "anyone")
	if !d.Allowed {
		t.Error("wildcard ACL entry should allow messaging anyone")
	}
}

func TestCheckACL_ACLEntries_FallbackToCanMessage(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"a": {
				ACLEntries: []config.ACLEntryConfig{
					{Target: "b"},
				},
				CanMessage: []string{"c"},
			},
		},
	}
	e := NewEvaluator(cfg)

	d := e.CheckACL("a", "c")
	if !d.Allowed {
		t.Error("should fall back to can_message when no ACL entry matches")
	}
}
