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
