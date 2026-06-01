package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
)

// ---- FIX B: LoadPolicyState fails closed on a present-but-malformed state ----

// stateTestConfigPath writes a minimal config to a temp dir and returns its
// path; the state file lives beside it.
func stateTestConfigPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "oktsec.yaml")
}

func TestLoadPolicyState_PresentButMalformedFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty_object", `{}`},
		{"targets_null", `{"version": 1, "targets": null}`},
		{"wrong_version", `{"version": 99, "targets": {}}`},
		{"missing_version", `{"targets": {}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := stateTestConfigPath(t)
			if err := os.WriteFile(PolicyStatePath(cfgPath), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write state: %v", err)
			}
			st, err := LoadPolicyState(cfgPath)
			if err == nil {
				t.Fatalf("present-but-malformed state must fail closed, got state %#v", st)
			}
			if st != nil {
				t.Fatalf("a failed load must return a nil state, got %#v", st)
			}
		})
	}
}

func TestLoadPolicyState_TruncatedGarbageFailsClosed(t *testing.T) {
	cfgPath := stateTestConfigPath(t)
	if err := os.WriteFile(PolicyStatePath(cfgPath), []byte(`{"version": 1, "targets": {`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if _, err := LoadPolicyState(cfgPath); err == nil {
		t.Fatalf("truncated state must fail closed")
	}
}

func TestLoadPolicyState_AbsentStartsFresh(t *testing.T) {
	cfgPath := stateTestConfigPath(t)
	st, err := LoadPolicyState(cfgPath)
	if err != nil {
		t.Fatalf("absent state must start fresh, got err: %v", err)
	}
	if st == nil || st.Targets == nil {
		t.Fatalf("fresh state must have a usable targets map, got %#v", st)
	}
	if len(st.Targets) != 0 {
		t.Fatalf("fresh state must be empty, got %#v", st.Targets)
	}
}

func TestLoadPolicyState_ValidPresentStillLoads(t *testing.T) {
	cfgPath := stateTestConfigPath(t)
	if err := os.WriteFile(PolicyStatePath(cfgPath), []byte(`{"version": 1, "targets": {}}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	st, err := LoadPolicyState(cfgPath)
	if err != nil {
		t.Fatalf("valid present state should load, got err: %v", err)
	}
	if st == nil || st.Targets == nil {
		t.Fatalf("want a usable state with a targets map, got %#v", st)
	}
}

// ---- FIX C: v1 DryRun clears ManagedByPolicy when it rewrites a rule ----

// v1OverrideBody builds a v1 PolicyBody (enforce mode) whose only rule action is
// an override of ruleID to "block". The projector consumes the verified body, so
// no signing is needed (verified is the shared in-package helper).
func v1OverrideBody(ruleID string) policybundle.PolicyBody {
	b := body()
	b.PolicyID = "pol-1"
	b.Rules.Overrides = map[string]policybundle.PolicyRuleOverride{ruleID: {Action: "block"}}
	return b
}

// saveTestConfig writes cfg to a temp file (apply never creates a config, so the
// file must exist before Commit) and returns its path.
func saveTestConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "oktsec.yaml")
	if err := cfg.Save(p); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return p
}

func TestV1DryRun_ClearsManagedByPolicyMarker(t *testing.T) {
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 8080},
		Agents:  map[string]config.Agent{"voice-ai": {AllowedTools: []string{"a"}}},
		Rules: []config.RuleAction{
			{ID: "IAP-001", Action: "allow-and-flag", ManagedByPolicy: true},
			{ID: "OP-LOCAL", Action: "block"}, // operator rule, never marked
		},
	}
	plan, err := DryRun(verified(v1OverrideBody("IAP-001")), cfg, "voice-ai", "/tmp/x.yaml")
	if err != nil {
		t.Fatalf("v1 dry-run: %v", err)
	}
	proj := plan.Projected()
	if proj == nil {
		t.Fatalf("expected a projected config")
	}
	var got *config.RuleAction
	for i := range proj.Rules {
		if proj.Rules[i].ID == "IAP-001" {
			got = &proj.Rules[i]
		}
	}
	if got == nil {
		t.Fatalf("IAP-001 should still exist after v1 override")
	}
	if got.Action != "block" {
		t.Fatalf("want action block, got %q", got.Action)
	}
	if got.ManagedByPolicy {
		t.Fatalf("v1 must clear ManagedByPolicy when it takes over a rule")
	}
}

// P2 #2: a v2-owned rule already AT the override's target action and global hits
// the no-action-change early return in upsert. The marker must STILL be cleared
// (so a later v2 replace cannot reap it), and that clear must be recorded as a
// distinct committable change (not a false action change) so it persists.
func TestV1DryRun_ClearsManagedByPolicyMarker_NoActionChange(t *testing.T) {
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 8080},
		Agents:  map[string]config.Agent{"voice-ai": {AllowedTools: []string{"a"}}},
		Rules: []config.RuleAction{
			// already global, already at the override target action ("block"),
			// and v2-owned: the upsert no-action-change early-return path.
			{ID: "IAP-001", Action: "block", ManagedByPolicy: true},
		},
	}
	plan, err := DryRun(verified(v1OverrideBody("IAP-001")), cfg, "voice-ai", "/tmp/x.yaml")
	if err != nil {
		t.Fatalf("v1 dry-run: %v", err)
	}
	proj := plan.Projected()
	if proj == nil {
		t.Fatalf("expected a projected config")
	}
	var got *config.RuleAction
	for i := range proj.Rules {
		if proj.Rules[i].ID == "IAP-001" {
			got = &proj.Rules[i]
		}
	}
	if got == nil {
		t.Fatalf("IAP-001 should still exist")
	}
	if got.ManagedByPolicy {
		t.Fatalf("marker must be cleared even when the action already matches")
	}
	// The clear is recorded as a marker-cleared change (so Commit runs and the
	// rules section is re-encoded) but never as a false rule_override.
	var markerCleared, falseOverride bool
	for _, c := range plan.Changes {
		if c.ID == "IAP-001" {
			switch c.Kind {
			case "rule_marker_cleared":
				markerCleared = true
			case "rule_override":
				falseOverride = true
			}
		}
	}
	if !markerCleared {
		t.Fatalf("expected a rule_marker_cleared change for IAP-001, got %+v", plan.Changes)
	}
	if falseOverride {
		t.Fatalf("must not report a false rule_override for an already-matching global rule")
	}
}

// P2 #2 (persistence): the marker clear must survive a real Commit even when it
// is the ONLY change. Without recording it as a committable change, the CLI skips
// Commit on an empty change set and the marker lingers on disk, leaving the
// v2-reap hazard in place. This is the end-to-end gap a projection-only test misses.
func TestV1Commit_PersistsMarkerClear_WhenOnlyChange(t *testing.T) {
	start := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 8080},
		Agents:  map[string]config.Agent{"voice-ai": {AllowedTools: []string{"a"}}},
		Rules: []config.RuleAction{
			// already at the override target action, global, v2-owned: marker clear
			// is the sole change.
			{ID: "IAP-001", Action: "block", ManagedByPolicy: true},
		},
	}
	cfgPath := saveTestConfig(t, start)
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	plan, err := DryRun(verified(v1OverrideBody("IAP-001")), c, "voice-ai", cfgPath)
	if err != nil {
		t.Fatalf("v1 dry-run: %v", err)
	}
	if len(plan.Changes) == 0 {
		t.Fatalf("marker-only clear must produce a committable change so Commit is not skipped")
	}
	if _, err := Commit(plan, cfgPath); err != nil {
		t.Fatalf("commit: %v", err)
	}
	after, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, r := range after.Rules {
		if r.ID == "IAP-001" && r.ManagedByPolicy {
			t.Fatalf("v1 commit must persist the cleared marker on disk, found managed_by_policy still set")
		}
	}
}

// TestV1ThenV2Replace_DoesNotReapV1OwnedRule asserts the end-to-end FIX C
// invariant: a rule first marked by v2, then rewritten by a v1 apply (which
// clears the marker and Commit-writes it), is NOT silently reaped by a later v2
// replace that omits the rule. Because the rule is now unmarked (operator/local)
// and unnamed by the bundle, the v2 replace must FAIL CLOSED (unowned local
// rule) rather than treat it as policy-owned and delete it.
func TestV1ThenV2Replace_DoesNotReapV1OwnedRule(t *testing.T) {
	start := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 8080},
		Agents:  map[string]config.Agent{"voice-ai": {AllowedTools: []string{"a"}}},
		Rules: []config.RuleAction{
			{ID: "IAP-001", Action: "allow-and-flag", ManagedByPolicy: true},
		},
	}
	cfgPath := saveTestConfig(t, start)

	// v1 takes over IAP-001 (override to block). This clears the marker.
	v1cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v1plan, err := DryRun(verified(v1OverrideBody("IAP-001")), v1cfg, "voice-ai", cfgPath)
	if err != nil {
		t.Fatalf("v1 dry-run: %v", err)
	}
	if _, err := Commit(v1plan, cfgPath); err != nil {
		t.Fatalf("v1 commit: %v", err)
	}

	// Confirm on disk the marker is gone (FIX C clear persisted by Commit).
	afterV1, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload after v1: %v", err)
	}
	for _, r := range afterV1.Rules {
		if r.ID == "IAP-001" && r.ManagedByPolicy {
			t.Fatalf("v1 commit must persist a cleared marker on IAP-001")
		}
	}

	// v2 replace that does NOT name IAP-001. Since IAP-001 is now unowned (marker
	// cleared) the replace must fail closed, not reap it.
	v2plan, err := DryRunV2(verifiedV2(rulesReplaceBody("IAP-OTHER")), afterV1, "", cfgPath)
	if err == nil {
		t.Fatalf("v2 replace over a now-unowned rule must fail closed (ErrUnsupported), got nil")
	}
	if !hasUnsupportedV2(v2plan, "rules_replace_unowned_local_rule") {
		t.Fatalf("expected rules_replace_unowned_local_rule unsupported entry; got %+v", v2plan.Unsupported)
	}
}

func TestV1YAMLByteFrozenWithMarker(t *testing.T) {
	mk := func(marked bool) string {
		cfg := &config.Config{
			Version: "1",
			Server:  config.ServerConfig{Port: 8080},
			Agents:  map[string]config.Agent{"voice-ai": {AllowedTools: []string{"a"}}},
			Rules:   []config.RuleAction{{ID: "IAP-001", Action: "allow-and-flag", ManagedByPolicy: marked}},
		}
		p := saveTestConfig(t, cfg)
		c, err := config.Load(p)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		plan, err := DryRun(verified(v1OverrideBody("IAP-001")), c, "voice-ai", p)
		if err != nil {
			t.Fatalf("v1 dry-run: %v", err)
		}
		if _, err := Commit(plan, p); err != nil {
			t.Fatalf("commit: %v", err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return string(b)
	}
	withMarker := mk(true)
	without := mk(false)
	if withMarker != without {
		t.Fatalf("v1 YAML must be byte-identical regardless of the input marker:\n--- marked ---\n%s\n--- unmarked ---\n%s", withMarker, without)
	}
	if strings.Contains(withMarker, "managed_by_policy") {
		t.Fatalf("v1 output must never emit managed_by_policy")
	}
}

// ---- FIX D: explicit false/0 v2 change values are emitted, not omitted ----

func TestChangeV2_ExplicitFalseAndZeroAreEmitted(t *testing.T) {
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 8080},
		Agents: map[string]config.Agent{
			"voice-ai": {AllowedTools: []string{"a"}, Suspended: true, BlockedContent: []string{"pii"}},
		},
		Rules: []config.RuleAction{},
	}
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: false}
	g.BlockedContent = policybundle.DimStringSetV2{Mode: dimClear, Values: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}

	plan, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}

	var sawSuspendFalse, sawClearZero bool
	for _, c := range plan.Changes {
		switch c.Kind {
		case "agent_suspended":
			if c.BoolValue == nil {
				t.Fatalf("suspended change must carry an explicit bool_value pointer, got nil")
			}
			if !*c.BoolValue {
				sawSuspendFalse = true
			}
		case "agent_blocked_content":
			if c.DimMode == "clear" {
				if c.Count == nil {
					t.Fatalf("clear change must carry an explicit count pointer, got nil")
				}
				if *c.Count == 0 {
					sawClearZero = true
				}
			}
		}
	}
	if !sawSuspendFalse {
		t.Fatalf("expected an agent_suspended change with explicit false; changes=%#v", plan.Changes)
	}
	if !sawClearZero {
		t.Fatalf("expected an agent_blocked_content clear with explicit count 0; changes=%#v", plan.Changes)
	}
}

func TestChangeV2_JSONEmitsExplicitFalseAndZero(t *testing.T) {
	suspend := ChangeV2{Kind: "agent_suspended", DimMode: "replace", Agent: "voice-ai", BoolValue: boolVal(false)}
	clear := ChangeV2{Kind: "agent_blocked_content", DimMode: "clear", Agent: "voice-ai", Count: intVal(0)}

	bs, err := json.Marshal(suspend)
	if err != nil {
		t.Fatalf("marshal suspend: %v", err)
	}
	if !strings.Contains(string(bs), `"bool_value":false`) {
		t.Fatalf("explicit false must be emitted, got %s", bs)
	}
	bc, err := json.Marshal(clear)
	if err != nil {
		t.Fatalf("marshal clear: %v", err)
	}
	if !strings.Contains(string(bc), `"count":0`) {
		t.Fatalf("explicit 0 count must be emitted, got %s", bc)
	}
}
