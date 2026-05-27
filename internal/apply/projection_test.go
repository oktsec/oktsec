package apply

import (
	"errors"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
)

const targetPath = "oktsec.yaml"

// baseConfig is a minimal valid config with two agents and one unrelated
// existing rule, used to prove scoping and preservation.
func baseConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Agents: map[string]config.Agent{
			"voice-ai": {AllowedTools: []string{"old.tool"}},
			"other":    {AllowedTools: []string{"keep.tool"}},
		},
		Rules: []config.RuleAction{{ID: "KEEP-1", Action: "block", Severity: "high"}},
	}
}

// verified wraps a PolicyBody as a (pre-)verified bundle; the projection
// operates on the verified body, so no signing is needed in these tests.
func verified(body policybundle.PolicyBody) *policybundle.VerifiedBundle {
	return &policybundle.VerifiedBundle{
		Bundle:     &policybundle.PolicyBundle{PolicyHash: "sha256:deadbeef", Policy: body},
		PolicyHash: "sha256:deadbeef",
	}
}

// body is a canonical-shape PolicyBody with empty containers, mutated per test.
func body() policybundle.PolicyBody {
	return policybundle.PolicyBody{
		PolicyID: "voice-ai-prod", PolicyVersion: "1", Mode: ModeEnforce,
		Rules:     policybundle.PolicyRules{Enabled: []string{}, Disabled: []string{}, Overrides: map[string]policybundle.PolicyRuleOverride{}},
		Gateway:   policybundle.PolicyGateway{ToolsAllowed: []string{}, ToolsDenied: []string{}},
		Egress:    policybundle.PolicyEgress{DomainsAllowed: []string{}, DomainsDenied: []string{}},
		Redaction: policybundle.PolicyRedaction{Level: "analyst"},
		Metadata:  policybundle.PolicyMetadata{CreatedAt: "2026-05-23T12:00:00Z", CreatedBy: "alice", Reason: "test"},
	}
}

func ruleAction(t *testing.T, p *Plan, id string) string {
	t.Helper()
	for _, c := range p.Changes {
		if c.Kind == "rule_override" && c.ID == id {
			return c.Action
		}
	}
	t.Fatalf("no rule_override change for %q in %+v", id, p.Changes)
	return ""
}

func TestDryRun_PlanShapeAndNoMutation(t *testing.T) {
	cfg := baseConfig()
	b := body()
	b.Rules.Enabled = []string{"IAP-001"}
	p, err := DryRun(verified(b), cfg, "voice-ai", targetPath)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if p.Applied || !p.DryRun {
		t.Fatalf("applied=%v dry_run=%v, want false/true", p.Applied, p.DryRun)
	}
	if p.PolicyHash != "sha256:deadbeef" || p.PolicyID != "voice-ai-prod" || p.PolicyVersion != "1" || p.Mode != "enforce" || p.Agent != "voice-ai" || p.TargetConfig != targetPath {
		t.Fatalf("plan header fields wrong: %+v", p)
	}
	// Input config must be untouched (projection works on a clone).
	if len(cfg.Rules) != 1 || cfg.Agents["voice-ai"].AllowedTools[0] != "old.tool" {
		t.Fatal("DryRun mutated the input config")
	}
}

func TestDryRun_MissingAgent(t *testing.T) {
	_, err := DryRun(verified(body()), baseConfig(), "ghost", targetPath)
	if !errors.Is(err, ErrMissingAgent) {
		t.Fatalf("err = %v, want ErrMissingAgent", err)
	}
}

func TestDryRun_EnabledAndDisabledRules(t *testing.T) {
	b := body()
	b.Rules.Enabled = []string{"IAP-001"}
	b.Rules.Disabled = []string{"IAP-002"}
	p, err := DryRun(verified(b), baseConfig(), "voice-ai", targetPath)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if got := ruleAction(t, p, "IAP-001"); got != "allow-and-flag" {
		t.Fatalf("enabled rule action = %q, want allow-and-flag", got)
	}
	if got := ruleAction(t, p, "IAP-002"); got != "ignore" {
		t.Fatalf("disabled rule action = %q, want ignore", got)
	}
}

func TestDryRun_OverrideActionMapping(t *testing.T) {
	cases := map[string]string{"flag": "allow-and-flag", "quarantine": "quarantine", "block": "block"}
	for ent, comm := range cases {
		b := body()
		b.Rules.Enabled = []string{"IAP-003"}
		b.Rules.Overrides = map[string]policybundle.PolicyRuleOverride{"IAP-003": {Action: ent}}
		p, err := DryRun(verified(b), baseConfig(), "voice-ai", targetPath)
		if err != nil {
			t.Fatalf("[%s] DryRun: %v", ent, err)
		}
		if got := ruleAction(t, p, "IAP-003"); got != comm {
			t.Fatalf("override %q mapped to %q, want %q", ent, got, comm)
		}
	}
}

func TestDryRun_ObserveDowngradesToAllowAndFlag(t *testing.T) {
	b := body()
	b.Mode = ModeObserve
	b.Rules.Enabled = []string{"IAP-003"}
	b.Rules.Overrides = map[string]policybundle.PolicyRuleOverride{"IAP-003": {Action: "block"}}
	p, err := DryRun(verified(b), baseConfig(), "voice-ai", targetPath)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if got := ruleAction(t, p, "IAP-003"); got != "allow-and-flag" {
		t.Fatalf("observe mode: block override projected as %q, want allow-and-flag", got)
	}
}

func TestDryRun_ToolsAndEgressScopedToSelectedAgent(t *testing.T) {
	b := body()
	b.Gateway.ToolsAllowed = []string{"calendar.read", "mail.read"}
	b.Egress.DomainsAllowed = []string{"api.openai.com"}
	b.Egress.DomainsDenied = []string{"evil.test"}
	p, err := DryRun(verified(b), baseConfig(), "voice-ai", targetPath)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	tgt := p.Projected()
	va := tgt.Agents["voice-ai"]
	if len(va.AllowedTools) != 2 || va.AllowedTools[0] != "calendar.read" {
		t.Fatalf("voice-ai allowed tools = %v", va.AllowedTools)
	}
	if va.Egress == nil || va.Egress.AllowedDomains[0] != "api.openai.com" || va.Egress.BlockedDomains[0] != "evil.test" {
		t.Fatalf("voice-ai egress not projected: %+v", va.Egress)
	}
	// The other agent must be untouched.
	other := tgt.Agents["other"]
	if len(other.AllowedTools) != 1 || other.AllowedTools[0] != "keep.tool" || other.Egress != nil {
		t.Fatalf("non-selected agent was modified: %+v", other)
	}
}

func TestDryRun_UnsupportedToolsDeniedWithoutAllowlist(t *testing.T) {
	b := body()
	b.Gateway.ToolsDenied = []string{"shell.exec"}
	p, err := DryRun(verified(b), baseConfig(), "voice-ai", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if len(p.Unsupported) != 1 || p.Unsupported[0].Kind != "gateway_tools_denied_without_allowlist" {
		t.Fatalf("unsupported = %+v", p.Unsupported)
	}
}

func TestDryRun_PreservesUnrelatedConfigAndValidates(t *testing.T) {
	b := body()
	b.Rules.Enabled = []string{"IAP-001"}
	b.Gateway.ToolsAllowed = []string{"calendar.read"}
	p, err := DryRun(verified(b), baseConfig(), "voice-ai", targetPath)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	tgt := p.Projected()
	if tgt == nil {
		t.Fatal("projected config must be returned")
	}
	if err := tgt.Validate(); err != nil {
		t.Fatalf("projected config must validate: %v", err)
	}
	// Unrelated existing rule preserved verbatim.
	var found bool
	for _, ra := range tgt.Rules {
		if ra.ID == "KEEP-1" {
			found = true
			if ra.Action != "block" || ra.Severity != "high" {
				t.Fatalf("unrelated rule KEEP-1 was modified: %+v", ra)
			}
		}
	}
	if !found {
		t.Fatal("unrelated rule KEEP-1 was dropped")
	}
}
