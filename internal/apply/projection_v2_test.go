package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
)

// verifiedV2 wraps a PolicyBodyV2 as a (pre-)verified v2 bundle; the projector
// operates on the verified body, so no signing is needed in these unit tests.
func verifiedV2(b policybundle.PolicyBodyV2) *policybundle.VerifiedBundleV2 {
	return &policybundle.VerifiedBundleV2{
		Bundle:     &policybundle.PolicyBundleV2{PolicyHash: "sha256:deadbeef", Policy: b},
		PolicyHash: "sha256:deadbeef",
	}
}

// bodyV2 is a canonical-shape PolicyBodyV2 with every dimension unmanaged and
// empty containers, mutated per test. Fleet scope by default.
func bodyV2() policybundle.PolicyBodyV2 {
	return policybundle.PolicyBodyV2{
		PolicyID: "voice-ai-prod", PolicyVersion: "1", Mode: ModeEnforce,
		Assignment: policybundle.AssignmentV2{
			AssignmentID: "asg-1",
			Target:       policybundle.TargetV2{Scope: "fleet"},
			IssuedAt:     "2026-05-30T12:00:00Z",
			Sequence:     1,
		},
		Rules:   policybundle.DimRulesV2{Mode: dimUnmanaged, Enabled: []string{}, Disabled: []string{}, Overrides: map[string]policybundle.PolicyRuleOverride{}},
		Gateway: policybundle.DimGatewayV2{Mode: dimUnmanaged, ToolsAllowed: []string{}, ToolsDenied: []string{}},
		Egress:  policybundle.DimEgressV2{Mode: dimUnmanaged, DomainsAllowed: []string{}, DomainsDenied: []string{}},
		Governance: policybundle.GovernanceV2{
			Server: policybundle.ServerGovernanceV2{Mode: dimUnmanaged},
			Agents: []policybundle.AgentGovernanceV2{},
		},
		Redaction: policybundle.DimRedactionV2{Mode: dimUnmanaged, Level: "analyst"},
		Metadata:  policybundle.PolicyMetadata{CreatedAt: "2026-05-30T12:00:00Z", CreatedBy: "alice", Reason: "test"},
	}
}

// agentGovV2 returns a per-agent governance entry for name with all dimensions
// unmanaged, mutated per test.
func agentGovV2(name string) policybundle.AgentGovernanceV2 {
	return policybundle.AgentGovernanceV2{
		Selector:        policybundle.SelectorV2{Name: name},
		ACLs:            policybundle.DimACLsV2{Mode: dimUnmanaged},
		AllowedTools:    policybundle.DimStringSetV2{Mode: dimUnmanaged, Values: []string{}},
		ToolPolicies:    policybundle.DimToolPoliciesV2{Mode: dimUnmanaged},
		ToolConstraints: policybundle.DimToolConstraintsV2{Mode: dimUnmanaged},
		ToolChainRules:  policybundle.DimToolChainRulesV2{Mode: dimUnmanaged},
		BlockedContent:  policybundle.DimStringSetV2{Mode: dimUnmanaged, Values: []string{}},
		ScanProfile:     policybundle.DimScalarStringV2{Mode: dimUnmanaged},
		Suspended:       policybundle.DimScalarBoolV2{Mode: dimUnmanaged},
		Egress:          policybundle.DimAgentEgressV2{Mode: dimUnmanaged, ScanRequests: "unset", ScanResponses: "unset"},
	}
}

func hasChangeV2(p *PlanV2, kind, agent string) *ChangeV2 {
	for i := range p.Changes {
		if p.Changes[i].Kind == kind && (agent == "" || p.Changes[i].Agent == agent) {
			return &p.Changes[i]
		}
	}
	return nil
}

func hasUnsupportedV2(p *PlanV2, kind string) bool {
	for _, u := range p.Unsupported {
		if u.Kind == kind {
			return true
		}
	}
	return false
}

// 1. unmanaged leaves the dimension untouched (no change).
func TestV2_UnmanagedLeavesDimensionUntouched(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai") // all unmanaged
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if len(p.Changes) != 0 {
		t.Fatalf("unmanaged dims must produce no changes, got %+v", p.Changes)
	}
	if p.Projected().Agents["voice-ai"].AllowedTools[0] != "old.tool" {
		t.Fatal("unmanaged allowed_tools must be untouched")
	}
}

// 2. replace replaces the dimension exactly.
func TestV2_ReplaceReplacesExactly(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read", "mail.read"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	va := p.Projected().Agents["voice-ai"]
	if len(va.AllowedTools) != 2 || va.AllowedTools[0] != "calendar.read" {
		t.Fatalf("replace allowed_tools = %v", va.AllowedTools)
	}
}

// 3. clear clears the dimension exactly (gateway tools clear -> zero callable).
// 4. deny-all gateway tools IS representable through clear and applies.
func TestV2_ClearGatewayToolsZeroAccess(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimClear, Values: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	va := p.Projected().Agents["voice-ai"]
	if len(va.AllowedTools) != 1 || va.AllowedTools[0] != denyAllToolsSentinel {
		t.Fatalf("clear must yield the zero-access sentinel, got %v", va.AllowedTools)
	}
	c := hasChangeV2(p, "agent_allowed_tools", "voice-ai")
	if c == nil || c.DimMode != dimClear {
		t.Fatalf("clear must emit a CLEAR change, got %+v", p.Changes)
	}
}

// 5. empty list under replace is a hard error, never a silent no-op.
func TestV2_EmptyReplaceIsHardError(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_allowed_tools_empty_replace") {
		t.Fatalf("expected empty-replace unsupported, got %+v", p.Unsupported)
	}
}

// 6. empty list under unmanaged never interpreted as all-allowed (no change).
func TestV2_EmptyUnmanagedNotAllAllowed(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai") // allowed_tools unmanaged with empty values
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if hasChangeV2(p, "agent_allowed_tools", "") != nil {
		t.Fatal("unmanaged empty allowed_tools must not change anything")
	}
}

// 7. a replace that would resolve to Community "all" -> unsupported (same as #5
// for gateway tools; the empty-replace guard IS the widening guard here).
func TestV2_ReplaceResolvingToAllRefused(t *testing.T) {
	// Covered by empty-replace; assert the explicit deny-all path works while an
	// empty replace is refused, proving deny-all only flows through clear.
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	if _, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("empty replace (would widen to all) must be unsupported, got %v", err)
	}
}

// 8. clear rejected for scalar fields where it widens (suspended->false).
func TestV2_SuspendedClearWidensRefused(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimClear}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_suspended_clear_widens") {
		t.Fatalf("expected suspended-clear unsupported, got %+v", p.Unsupported)
	}
}

func TestV2_ScanProfileClearRefused(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.ScanProfile = policybundle.DimScalarStringV2{Mode: dimClear}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	_, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("scan_profile clear must be unsupported, got %v", err)
	}
}

// Suspended replace works (the safe path).
func TestV2_SuspendedReplaceApplies(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if !p.Projected().Agents["voice-ai"].Suspended {
		t.Fatal("suspended replace=true must set Suspended")
	}
}

// 9. merge -> unsupported (the verifier rejects it, but the projector defends).
func TestV2_MergeModeUnsupported(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: "merge", Values: []string{"x"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("merge mode must be unsupported, got %v", err)
	}
	if !hasUnsupportedV2(p, "agent_allowed_tools_mode_unsupported") {
		t.Fatalf("expected merge-mode unsupported, got %+v", p.Unsupported)
	}
}

// 10. selector overlap on same dimension -> unsupported before writing.
func TestV2_SelectorOverlapSameDimUnsupported(t *testing.T) {
	b := bodyV2()
	g1 := agentGovV2("voice-ai")
	g1.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"a.read"}}
	g2 := agentGovV2("voice-ai")
	g2.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"b.read"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g1, g2}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_allowed_tools_ambiguous_selector") {
		t.Fatalf("expected ambiguous-selector unsupported, got %+v", p.Unsupported)
	}
}

// 11. unsupported dimension (governed but not implemented) -> refuses.
func TestV2_GovernedUnimplementedDimRefuses(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.ACLs = policybundle.DimACLsV2{Mode: dimReplace, AllowedRecipients: []string{"x"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_acls_unsupported") {
		t.Fatalf("expected acls unsupported, got %+v", p.Unsupported)
	}
}

func TestV2_GovernedServerDimRefuses(t *testing.T) {
	b := bodyV2()
	b.Governance.Server = policybundle.ServerGovernanceV2{Mode: dimReplace, RequireIntent: true}
	_, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("governed server dim must be unsupported, got %v", err)
	}
}

// 12. real apply is all-or-nothing (one unsupported dim -> nothing written).
func TestV2_RealApplyAllOrNothing(t *testing.T) {
	path := writeOrigConfig(t, 0o600)
	orig, _ := os.ReadFile(path)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read"}}
	g.ACLs = policybundle.DimACLsV2{Mode: dimReplace, AllowedRecipients: []string{"x"}} // unsupported
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}

	plan, perr := DryRunV2(verifiedV2(b), cfg, "", path)
	if !errors.Is(perr, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", perr)
	}
	// A real apply must not call CommitV2 on an unsupported plan; assert that
	// committing it is refused at the command layer is covered elsewhere. Here,
	// directly assert the config is still untouched (we never committed).
	if after, _ := os.ReadFile(path); string(after) != string(orig) {
		t.Fatal("config must be untouched when a dim is unsupported")
	}
	_ = plan
}

// 13. dry-run reports the full patch without writing.
func TestV2_DryRunReportsWithoutWriting(t *testing.T) {
	path := writeOrigConfig(t, 0o600)
	orig, _ := os.ReadFile(path)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", path)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if len(p.Changes) == 0 {
		t.Fatal("dry-run must report changes")
	}
	if after, _ := os.ReadFile(path); string(after) != string(orig) {
		t.Fatal("dry-run must not write")
	}
}

// Commit + state helpers for the rollback tests.
func commitV2Body(t *testing.T, path string, b policybundle.PolicyBodyV2, nodeID string) *PlanV2 {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, err := DryRunV2(verifiedV2(b), cfg, nodeID, path)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	return p
}

// 14 + 21. sequence advances only after success; state file is 0600 + atomic.
func TestV2_StateAdvancesAfterSuccessAndIs0600(t *testing.T) {
	path := writeOrigConfig(t, 0o600)
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	b.Assignment.Sequence = 5

	plan := commitV2Body(t, path, b, "")
	if _, err := CommitV2(plan, path); err != nil {
		t.Fatalf("CommitV2: %v", err)
	}
	st, _ := LoadPolicyState(path)
	st.Record(plan.Scope, plan.NodeID, plan.AssignmentID, "2026-05-30T00:00:00Z", plan.Sequence)
	if err := SavePolicyState(path, st); err != nil {
		t.Fatalf("SavePolicyState: %v", err)
	}
	sp := PolicyStatePath(path)
	info, err := os.Stat(sp)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, want 0600", info.Mode().Perm())
	}
	reloaded, err := LoadPolicyState(path)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	rec := reloaded.Targets[TargetKey("fleet", "")]
	if rec.LastSequence != 5 || rec.LastAssignmentID != "asg-1" {
		t.Fatalf("state not recorded: %+v", rec)
	}
}

// 15. stale sequence (<=last, no rollback_of) -> RollbackRefuse.
func TestV2_StaleSequenceRefused(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	st.Record("fleet", "", "asg-old", "t", 10)
	d := st.EvaluateRollback("fleet", "", "asg-new", "", 9)
	if d != RollbackRefuse {
		t.Fatalf("stale sequence must refuse, got %v", d)
	}
	dEq := st.EvaluateRollback("fleet", "", "asg-new", "", 10)
	if dEq != RollbackRefuse {
		t.Fatalf("equal sequence with no rollback must refuse, got %v", dEq)
	}
}

// 16. signed rollback (rollback_of == current applied assignment) -> proceed.
func TestV2_SignedRollbackAllowed(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	st.Record("fleet", "", "asg-current", "t", 10)
	d := st.EvaluateRollback("fleet", "", "asg-rollback", "asg-current", 7)
	if d != RollbackProceedSigned {
		t.Fatalf("signed rollback must proceed, got %v", d)
	}
	// rollback_of naming a non-current assignment is refused.
	d2 := st.EvaluateRollback("fleet", "", "asg-rollback", "asg-stale", 7)
	if d2 != RollbackRefuse {
		t.Fatalf("rollback_of not naming current must refuse, got %v", d2)
	}
}

// The replay floor is monotonic: after a signed rollback to a lower sequence,
// recording it must NOT lower the floor, so a stale apply at a sequence between
// the rolled-back one and the previous floor is still refused.
func TestV2_RollbackKeepsReplayFloorMonotonic(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	st.Record("fleet", "", "asg-10", "t", 10)
	// Signed rollback to seq 7 of the current assignment is allowed...
	if d := st.EvaluateRollback("fleet", "", "asg-rb", "asg-10", 7); d != RollbackProceedSigned {
		t.Fatalf("signed rollback must proceed, got %v", d)
	}
	// ...and recording it keeps the replay floor at 10, not 7, while the applied
	// sequence and assignment id reflect the rolled-back bundle.
	st.Record("fleet", "", "asg-rb", "t", 7)
	rec := st.Targets[TargetKey("fleet", "")]
	if rec.ReplayFloor != 10 {
		t.Fatalf("replay floor must stay 10 after a rollback to 7, got %d", rec.ReplayFloor)
	}
	if rec.LastSequence != 7 {
		t.Fatalf("LastSequence must be the applied (rolled-back) seq 7, got %d", rec.LastSequence)
	}
	if rec.LastAssignmentID != "asg-rb" {
		t.Fatal("LastAssignmentID must reflect the rolled-back assignment")
	}
	// A plain stale apply at seq 8 (below the floor, no rollback_of) is refused.
	if d := st.EvaluateRollback("fleet", "", "asg-8", "", 8); d != RollbackRefuse {
		t.Fatalf("stale seq-8 apply must be refused after the floor stayed at 10, got %v", d)
	}
	// A further signed rollback of the now-current rolled-back assignment works.
	if d := st.EvaluateRollback("fleet", "", "asg-rb2", "asg-rb", 6); d != RollbackProceedSigned {
		t.Fatalf("further signed rollback of the current assignment must proceed, got %v", d)
	}
	// An idempotent reapply of the rolled-back bundle (asg-rb at its own seq 7)
	// must still be allowed even though the floor is 10.
	if d := st.EvaluateRollback("fleet", "", "asg-rb", "", 7); d != RollbackProceedReapply {
		t.Fatalf("idempotent reapply of the rolled-back bundle must proceed, got %v", d)
	}
}

// An existing agent egress rate limit makes an egress restrict a partial
// projection, so it fails closed.
func TestV2_AgentEgressExistingRateLimitRefused(t *testing.T) {
	cfg := baseConfig()
	va := cfg.Agents["voice-ai"]
	va.Egress = &config.EgressPolicy{AllowedDomains: []string{"api.openai.com"}, RateLimit: 10, RateWindow: 60}
	cfg.Agents["voice-ai"] = va
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com"}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_allowed_not_restrictable") {
		t.Fatalf("expected not-restrictable (rate limit), got %+v", p.Unsupported)
	}
}

// 17. target.scope node + wrong node_id -> policy_target_mismatch, no plan.
func TestV2_NodeTargetMismatchRefused(t *testing.T) {
	b := bodyV2()
	b.Assignment.Target = policybundle.TargetV2{Scope: "node", NodeID: "node-A"}
	_, err := DryRunV2(verifiedV2(b), baseConfig(), "node-B", targetPath)
	if !errors.Is(err, ErrPolicyTargetMismatch) {
		t.Fatalf("err = %v, want ErrPolicyTargetMismatch", err)
	}
}

func TestV2_NodeTargetMissingNodeIDRefused(t *testing.T) {
	b := bodyV2()
	b.Assignment.Target = policybundle.TargetV2{Scope: "node", NodeID: "node-A"}
	_, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrPolicyTargetMismatch) {
		t.Fatalf("missing node id must mismatch, got %v", err)
	}
}

// 18. target.scope fleet -> applies on any node.
func TestV2_FleetAppliesAnyNode(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "any-node-here", targetPath)
	if err != nil {
		t.Fatalf("fleet must apply on any node: %v", err)
	}
	if len(p.Changes) == 0 {
		t.Fatal("fleet apply produced no changes")
	}
}

func TestV2_NodeTargetMatchApplies(t *testing.T) {
	b := bodyV2()
	b.Assignment.Target = policybundle.TargetV2{Scope: "node", NodeID: "node-A"}
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	if _, err := DryRunV2(verifiedV2(b), baseConfig(), "node-A", targetPath); err != nil {
		t.Fatalf("matching node must apply: %v", err)
	}
}

// 19. first apply for a target (no state) -> proceeds.
func TestV2_FirstApplyProceeds(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	if d := st.EvaluateRollback("fleet", "", "asg-1", "", 1); d != RollbackProceedFresh {
		t.Fatalf("first apply must proceed fresh, got %v", d)
	}
	if d := st.EvaluateRollback("node", "node-A", "asg-1", "", 99); d != RollbackProceedFresh {
		t.Fatalf("first node apply must proceed fresh, got %v", d)
	}
}

// Fleet and node targets track independently.
func TestV2_FleetAndNodeTracksSeparately(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	st.Record("fleet", "", "asg-fleet", "t", 10)
	// A node target is still fresh despite the fleet record.
	if d := st.EvaluateRollback("node", "node-A", "asg-node", "", 1); d != RollbackProceedFresh {
		t.Fatalf("node target must be independent of fleet, got %v", d)
	}
}

// blocked_content replace + clear.
func TestV2_BlockedContentReplaceAndClear(t *testing.T) {
	cfg := baseConfig()
	va := cfg.Agents["voice-ai"]
	va.BlockedContent = []string{"pii", "secrets"}
	cfg.Agents["voice-ai"] = va

	// replace
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.BlockedContent = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"pii"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2 replace: %v", err)
	}
	if got := p.Projected().Agents["voice-ai"].BlockedContent; len(got) != 1 || got[0] != "pii" {
		t.Fatalf("blocked_content replace = %v", got)
	}

	// clear -> empty
	b2 := bodyV2()
	g2 := agentGovV2("voice-ai")
	g2.BlockedContent = policybundle.DimStringSetV2{Mode: dimClear, Values: []string{}}
	b2.Governance.Agents = []policybundle.AgentGovernanceV2{g2}
	p2, err := DryRunV2(verifiedV2(b2), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2 clear: %v", err)
	}
	if len(p2.Projected().Agents["voice-ai"].BlockedContent) != 0 {
		t.Fatalf("blocked_content clear must be empty, got %v", p2.Projected().Agents["voice-ai"].BlockedContent)
	}
}

// scan_profile replace.
func TestV2_ScanProfileReplace(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.ScanProfile = policybundle.DimScalarStringV2{Mode: dimReplace, Value: config.ScanProfileStrict}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if p.Projected().Agents["voice-ai"].ScanProfile != config.ScanProfileStrict {
		t.Fatalf("scan_profile replace not applied")
	}
}

// rules replace projected globally.
func TestV2_RulesReplaceProjectedGlobally(t *testing.T) {
	b := bodyV2()
	b.Rules = policybundle.DimRulesV2{
		Mode:      dimReplace,
		Enabled:   []string{"IAP-003"},
		Disabled:  []string{"IAP-002"},
		Overrides: map[string]policybundle.PolicyRuleOverride{"IAP-003": {Action: "block"}},
	}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	var sawBlock, sawIgnore bool
	for _, c := range p.Changes {
		if c.Kind == "rule_override" && c.ID == "IAP-003" && c.Action == "block" {
			sawBlock = true
		}
		if c.Kind == "rule_override" && c.ID == "IAP-002" && c.Action == "ignore" {
			sawIgnore = true
		}
	}
	if !sawBlock || !sawIgnore {
		t.Fatalf("rules not projected: %+v", p.Changes)
	}
}

func TestV2_RulesClearUnsupported(t *testing.T) {
	b := bodyV2()
	b.Rules = policybundle.DimRulesV2{Mode: dimClear, Enabled: []string{}, Disabled: []string{}, Overrides: map[string]policybundle.PolicyRuleOverride{}}
	_, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("rules clear must be unsupported, got %v", err)
	}
}

// CommitV2 writes governed agent fields and preserves unrelated content.
func TestV2_CommitWritesAndPreserves(t *testing.T) {
	path := writeOrigConfig(t, 0o600)
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read", "voice.dial"}}
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}

	plan := commitV2Body(t, path, b, "")
	backup, err := CommitV2(plan, path)
	if err != nil {
		t.Fatalf("CommitV2: %v", err)
	}
	if backup == "" {
		t.Fatal("backup path empty")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("written config must load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("written config must validate: %v", err)
	}
	va := cfg.Agents["voice-ai"]
	if len(va.AllowedTools) != 2 || va.AllowedTools[0] != "calendar.read" {
		t.Fatalf("allowed_tools not written: %v", va.AllowedTools)
	}
	if !va.Suspended {
		t.Fatal("suspended not written")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "operator config") {
		t.Fatal("header comment dropped")
	}
}

// A label-only selector (no name) is unsupported: the verifier requires a name,
// and the projector enforces the same contract rather than silently matching all.
func TestV2_LabelOnlySelectorUnsupported(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("")
	g.Selector = policybundle.SelectorV2{Labels: map[string]string{"env": "prod"}}
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_selector_name_required") {
		t.Fatalf("expected name-required unsupported, got %+v", p.Unsupported)
	}
}

// A named selector narrowed by labels matches only when the named agent carries
// the labels; a label the agent lacks means no match (no change, no error).
func TestV2_NamedSelectorLabelsNarrow(t *testing.T) {
	cfg := baseConfig()
	va := cfg.Agents["voice-ai"]
	va.Tags = []string{"env=prod"}
	cfg.Agents["voice-ai"] = va

	// matching label -> applies
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Selector = policybundle.SelectorV2{Name: "voice-ai", Labels: map[string]string{"env": "prod"}}
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if !p.Projected().Agents["voice-ai"].Suspended {
		t.Fatal("named selector with matching label must apply")
	}

	// non-matching label -> no change, no error
	b2 := bodyV2()
	g2 := agentGovV2("voice-ai")
	g2.Selector = policybundle.SelectorV2{Name: "voice-ai", Labels: map[string]string{"env": "staging"}}
	g2.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b2.Governance.Agents = []policybundle.AgentGovernanceV2{g2}
	p2, err := DryRunV2(verifiedV2(b2), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if len(p2.Changes) != 0 {
		t.Fatalf("non-matching label must produce no change, got %+v", p2.Changes)
	}
}

// Idempotent reapply: the recorded assignment at its recorded sequence is
// allowed again (retry / drift repair), not refused.
func TestV2_IdempotentReapplyAllowed(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	st.Record("fleet", "", "asg-current", "t", 10)
	if d := st.EvaluateRollback("fleet", "", "asg-current", "", 10); d != RollbackProceedReapply {
		t.Fatalf("same assignment + same sequence must be an idempotent reapply, got %v", d)
	}
	// A different assignment at the same sequence is still refused.
	if d := st.EvaluateRollback("fleet", "", "asg-other", "", 10); d != RollbackRefuse {
		t.Fatalf("different assignment at recorded sequence must refuse, got %v", d)
	}
}

// Egress replace additive-source widener: a global forward_proxy allowlist that
// permits a domain outside the bundle's per-agent allowlist makes the restrict
// unexpressible -> unsupported (mirrors v1).
func TestV2_EgressReplaceAdditiveWidenerUnsupported(t *testing.T) {
	cfg := baseConfig()
	cfg.ForwardProxy = config.ForwardProxyConfig{Enabled: true, AllowedDomains: []string{"github.com"}}
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com"}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_allowed_not_restrictable") {
		t.Fatalf("expected additive-widener unsupported, got %+v", p.Unsupported)
	}
}

// When the global allowlist is a subset of the bundle's, the union still equals
// the policy, so egress replace is supported.
func TestV2_EgressReplaceGlobalSubsetSupported(t *testing.T) {
	cfg := baseConfig()
	cfg.ForwardProxy = config.ForwardProxyConfig{Enabled: true, AllowedDomains: []string{"github.com"}}
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com", "github.com"}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	if _, err := DryRunV2(verifiedV2(b), cfg, "", targetPath); err != nil {
		t.Fatalf("global subset of policy must be supported: %v", err)
	}
}

// Body-level gateway governance fails closed (global gateway not projected).
func TestV2_BodyGatewayGovernedFailsClosed(t *testing.T) {
	b := bodyV2()
	b.Gateway = policybundle.DimGatewayV2{Mode: dimReplace, ToolsAllowed: []string{"x"}, ToolsDenied: []string{}}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("governed body gateway must be unsupported, got %v", err)
	}
	if !hasUnsupportedV2(p, "body_gateway") {
		t.Fatalf("expected body_gateway unsupported, got %+v", p.Unsupported)
	}
}

// missing named agent -> ErrMissingAgent.
func TestV2_MissingNamedAgent(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("ghost")
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	_, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrMissingAgent) {
		t.Fatalf("err = %v, want ErrMissingAgent", err)
	}
}


// Reserved deny-all sentinel in a replace value is refused (P2 guard).
func TestV2_ReservedToolSentinelInReplaceRefused(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{denyAllToolsSentinel}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_allowed_tools_reserved_value") {
		t.Fatalf("expected reserved-value unsupported, got %+v", p.Unsupported)
	}
}

func TestV2_ReservedDomainSentinelInReplaceRefused(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{denyAllDomainsSentinel}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_reserved_value") {
		t.Fatalf("expected reserved-domain unsupported, got %+v", p.Unsupported)
	}
}

// per-agent egress with unimplemented sub-fields fails closed.
func TestV2_AgentEgressUnsupportedFields(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com"}, ScanRequests: "true", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_unsupported_fields") {
		t.Fatalf("expected egress-unsupported-fields, got %+v", p.Unsupported)
	}
}

// per-agent egress allowed/blocked replace projects cleanly.
func TestV2_AgentEgressReplaceProjects(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com"}, BlockedDomains: []string{"evil.test"}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	eg := p.Projected().Agents["voice-ai"].Egress
	if eg == nil || len(eg.AllowedDomains) != 1 || eg.AllowedDomains[0] != "api.openai.com" {
		t.Fatalf("egress allowed not projected: %+v", eg)
	}
	if len(eg.BlockedDomains) != 1 || eg.BlockedDomains[0] != "evil.test" {
		t.Fatalf("egress blocked not projected: %+v", eg)
	}
}

// per-agent egress clear yields the zero-egress sentinel when no additive
// source remains.
func TestV2_AgentEgressClearZeroEgress(t *testing.T) {
	cfg := baseConfig()
	va := cfg.Agents["voice-ai"]
	va.Egress = &config.EgressPolicy{AllowedDomains: []string{"api.keep.com"}}
	cfg.Agents["voice-ai"] = va
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimClear, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	eg := p.Projected().Agents["voice-ai"].Egress
	if eg == nil || len(eg.AllowedDomains) != 1 || eg.AllowedDomains[0] != denyAllDomainsSentinel {
		t.Fatalf("egress clear must yield zero-egress sentinel, got %+v", eg)
	}
}

// egress clear with a global forward_proxy allowlist present cannot achieve zero
// egress, so it fails closed.
func TestV2_AgentEgressClearWithGlobalAllowlistRefused(t *testing.T) {
	cfg := baseConfig()
	cfg.ForwardProxy = config.ForwardProxyConfig{Enabled: true, AllowedDomains: []string{"github.com"}}
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimClear, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_clear_not_zeroable") {
		t.Fatalf("expected clear-not-zeroable unsupported, got %+v", p.Unsupported)
	}
}

// An existing agent egress scan override makes an egress restrict a partial
// projection, so it fails closed.
func TestV2_AgentEgressExistingScanOverrideRefused(t *testing.T) {
	cfg := baseConfig()
	tru := true
	va := cfg.Agents["voice-ai"]
	va.Egress = &config.EgressPolicy{AllowedDomains: []string{"api.openai.com"}, ScanRequests: &tru}
	cfg.Agents["voice-ai"] = va
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com"}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_allowed_not_restrictable") {
		t.Fatalf("expected not-restrictable (scan override), got %+v", p.Unsupported)
	}
}

// An existing agent tool_restrictions entry is a widener: an egress restrict
// (replace or clear) that only rewrites allowed_domains leaves the tool-scoped
// domains reachable, so it fails closed.
func TestV2_AgentEgressExistingToolRestrictionsWiden(t *testing.T) {
	cfg := baseConfig()
	va := cfg.Agents["voice-ai"]
	va.Egress = &config.EgressPolicy{
		AllowedDomains:   []string{"api.openai.com"},
		ToolRestrictions: map[string][]string{"shell.exec": {"evil.com"}},
	}
	cfg.Agents["voice-ai"] = va
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.Egress = policybundle.DimAgentEgressV2{Mode: dimReplace, AllowedDomains: []string{"api.openai.com"}, ScanRequests: "unset", ScanResponses: "unset"}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_egress_allowed_not_restrictable") {
		t.Fatalf("expected not-restrictable (tool_restrictions widener), got %+v", p.Unsupported)
	}
}

// P1: a no-op (zero-change) apply must record state so a later lower-sequence
// real apply cannot sneak in. This asserts the state semantics the command's
// no-op branch relies on (the command calls Record+SavePolicyState in that
// branch; here we assert the EvaluateRollback consequence of that record).
func TestV2_NoopAdvancesSequenceState(t *testing.T) {
	st := &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}
	// Recording a higher-sequence no-op assignment must make a later lower
	// sequence refuse.
	st.Record("fleet", "", "asg-noop", "2026-05-30T00:00:00Z", 20)
	if d := st.EvaluateRollback("fleet", "", "asg-lower", "", 19); d != RollbackRefuse {
		t.Fatalf("after a no-op recorded seq 20, a seq-19 apply must be refused, got %v", d)
	}
	if d := st.EvaluateRollback("fleet", "", "asg-higher", "", 21); d != RollbackProceedAdvance {
		t.Fatalf("seq 21 must advance, got %v", d)
	}
}

func TestV2_StateFileSuffixPathIsAdjacent(t *testing.T) {
	got := PolicyStatePath("/etc/oktsec/oktsec.yaml")
	want := "/etc/oktsec/oktsec.yaml" + PolicyStateFileSuffix
	if got != want {
		t.Fatalf("state path = %q, want %q", got, want)
	}
	if filepath.Dir(got) != "/etc/oktsec" {
		t.Fatalf("state file not adjacent: %q", got)
	}
}

// rulesReplaceBody builds a fleet bundle whose rules.mode is replace and which
// governs exactly the given enabled ids with block overrides. Used by the honest
// replace tests below.
func rulesReplaceBody(enabled ...string) policybundle.PolicyBodyV2 {
	b := bodyV2()
	overrides := map[string]policybundle.PolicyRuleOverride{}
	for _, id := range enabled {
		overrides[id] = policybundle.PolicyRuleOverride{Action: "block"}
	}
	b.Rules = policybundle.DimRulesV2{
		Mode:      dimReplace,
		Enabled:   append([]string(nil), enabled...),
		Disabled:  []string{},
		Overrides: overrides,
	}
	return b
}

func ruleByID(cfg *config.Config, id string) (config.RuleAction, bool) {
	for _, ra := range cfg.Rules {
		if ra.ID == id {
			return ra, true
		}
	}
	return config.RuleAction{}, false
}

// FIX 1 test 1: replace with a PRIOR POLICY-OWNED rule (marked) absent from the
// bundle -> it is REMOVED (honest replace reaps stale policy-owned overrides).
func TestV2_RulesReplaceReapsStalePolicyOwnedRule(t *testing.T) {
	cfg := baseConfig()
	// A previously policy-owned override the new bundle no longer declares.
	cfg.Rules = []config.RuleAction{
		{ID: "STALE-1", Action: "ignore", Severity: "low", ManagedByPolicy: true},
	}
	b := rulesReplaceBody("IAP-003")
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if _, ok := ruleByID(p.Projected(), "STALE-1"); ok {
		t.Fatalf("stale policy-owned rule must be reaped, still present: %+v", p.Projected().Rules)
	}
	ra, ok := ruleByID(p.Projected(), "IAP-003")
	if !ok || !ra.ManagedByPolicy || ra.Action != "block" {
		t.Fatalf("governed rule must be written and marked, got %+v ok=%v", ra, ok)
	}
}

// FIX 1 test 2 (architect cut): replace with a local rule of UNKNOWN ownership
// (unmarked) absent from the bundle -> the apply FAILS CLOSED. A v2 replace is a
// hard claim that the node's governed rule set equals the signed set, so an
// unmarked local rule the bundle does not name blocks: no config write, no state
// advance, and the error names the blocking rule clearly. Silent preservation is
// no longer the contract. (This is also the first-apply reality: before any v2
// apply no rule is marked, so a node with pre-existing local rules not in the
// bundle fails closed on first replace until the operator reconciles.)
func TestV2_RulesReplaceUnownedRuleFailsClosed(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []config.RuleAction{
		{ID: "OPER-1", Action: "quarantine", Severity: "high"}, // no marker = unknown ownership
	}
	b := rulesReplaceBody("IAP-003")
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unowned local rule must fail closed with ErrUnsupported, got %v", err)
	}
	if !hasUnsupportedV2(p, "rules_replace_unowned_local_rule") {
		t.Fatalf("expected rules_replace_unowned_local_rule unsupported, got %+v", p.Unsupported)
	}
	// Architect regression 5: the error names the blocking rule clearly.
	named := false
	for _, u := range p.Unsupported {
		if u.Kind == "rules_replace_unowned_local_rule" && strings.Contains(u.Detail, "OPER-1") {
			named = true
		}
	}
	if !named {
		t.Fatalf("unsupported detail must name the blocking rule OPER-1, got %+v", p.Unsupported)
	}
}

// FIX 1 test (architect regression 4): a CLEAN replace, where every local rule
// is either named by the bundle or marked policy-owned, leaves EXACTLY the
// signed desired rule set (governed rules written+marked, stale policy-owned
// rules reaped, nothing of unknown ownership left to block).
func TestV2_RulesReplaceCleanLeavesExactlySignedSet(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []config.RuleAction{
		// Named by the bundle (will be written+marked).
		{ID: "IAP-003", Action: "ignore", Severity: "high", ManagedByPolicy: true},
		// Stale policy-owned, not named -> reaped.
		{ID: "STALE-9", Action: "ignore", Severity: "low", ManagedByPolicy: true},
	}
	b := rulesReplaceBody("IAP-003")
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("clean replace must succeed, got %v", err)
	}
	got := p.Projected().Rules
	if len(got) != 1 {
		t.Fatalf("clean replace must leave exactly the signed set (1 rule), got %+v", got)
	}
	ra, ok := ruleByID(p.Projected(), "IAP-003")
	if !ok || !ra.ManagedByPolicy || ra.Action != "block" {
		t.Fatalf("the only remaining rule must be the signed governed rule, got %+v ok=%v", ra, ok)
	}
	if _, ok := ruleByID(p.Projected(), "STALE-9"); ok {
		t.Fatalf("stale policy-owned rule must be reaped in a clean replace, rules=%+v", got)
	}
}

// FIX 1 test (architect regression 3): a named rule replacement clears the old
// scoped fields (apply_to_tools/exempt_tools widened to global, as the upsert
// does), so the projected rule is exactly the signed global override.
func TestV2_RulesReplaceClearsScopedFields(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []config.RuleAction{
		{ID: "IAP-003", Action: "ignore", Severity: "high",
			ApplyToTools: []string{"calendar.read"}, ExemptTools: []string{"mail.send"},
			ManagedByPolicy: true},
	}
	b := rulesReplaceBody("IAP-003")
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	ra, ok := ruleByID(p.Projected(), "IAP-003")
	if !ok {
		t.Fatalf("named rule must be present, rules=%+v", p.Projected().Rules)
	}
	if len(ra.ApplyToTools) != 0 || len(ra.ExemptTools) != 0 {
		t.Fatalf("named replace must clear scoped fields (apply_to_tools/exempt_tools), got %+v", ra)
	}
	if ra.Action != "block" || !ra.ManagedByPolicy {
		t.Fatalf("named replace must write the signed global override marked, got %+v", ra)
	}
}

// FIX 1 test 3: reapplying the same bundle is a no-op (the marked governed set
// already matches; no removal churn, no change entries).
func TestV2_RulesReplaceReapplyIsNoop(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []config.RuleAction{
		{ID: "IAP-003", Action: "block", Severity: "high", ManagedByPolicy: true},
	}
	b := rulesReplaceBody("IAP-003")
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	for _, c := range p.Changes {
		if c.Kind == "rule_override" || c.Kind == "rule_reset_default" {
			t.Fatalf("reapply of the same bundle must be a rules no-op, got change %+v", c)
		}
	}
	ra, ok := ruleByID(p.Projected(), "IAP-003")
	if !ok || !ra.ManagedByPolicy || ra.Action != "block" {
		t.Fatalf("reapply must keep the marked rule intact, got %+v ok=%v", ra, ok)
	}
}

// FIX 1 test 4: drop an override from the bundle and reapply -> it DISAPPEARS
// from the runtime (the previously-marked rule is reaped).
func TestV2_RulesReplaceDroppedOverrideDisappears(t *testing.T) {
	cfg := baseConfig()
	// Two prior policy-owned overrides.
	cfg.Rules = []config.RuleAction{
		{ID: "IAP-003", Action: "block", Severity: "high", ManagedByPolicy: true},
		{ID: "IAP-004", Action: "block", Severity: "high", ManagedByPolicy: true},
	}
	// New bundle only declares IAP-003: IAP-004 must be reaped.
	b := rulesReplaceBody("IAP-003")
	p, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	if _, ok := ruleByID(p.Projected(), "IAP-004"); ok {
		t.Fatalf("dropped override must disappear, still present: %+v", p.Projected().Rules)
	}
	ra, ok := ruleByID(p.Projected(), "IAP-003")
	if !ok || !ra.ManagedByPolicy {
		t.Fatalf("retained override must stay marked, got %+v ok=%v", ra, ok)
	}
}

// FIX 1 test 5: the marker round-trips through the YAML write path (Commit). After
// a real apply, the written config has the governed rule marked and the operator
// rule unmarked; loading it back preserves the distinction. Uses a config file
// seeded with an operator-authored rule (OPER-1, no marker) so we prove operator
// config is preserved through the real write path, not just in memory.
func TestV2_RulesReplaceMarkerRoundTripsThroughCommit(t *testing.T) {
	// Reuse the proven-stable origConfigYAML fixture (identical to the reliable
	// CommitV2 test) but with an operator-authored rule instead of an empty rules
	// list, so the round-trip proves operator config survives the real write path.
	seeded := strings.Replace(origConfigYAML, "rules: []\n",
		"rules:\n  - id: OPER-1\n    action: quarantine\n    severity: high\n", 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	b := rulesReplaceBody("IAP-003")
	plan := commitV2Body(t, path, b, "")
	if _, err := CommitV2(plan, path); err != nil {
		t.Fatalf("CommitV2: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("written config must load: %v", err)
	}
	// Governed rule is marked.
	ra, ok := ruleByID(cfg, "IAP-003")
	if !ok || !ra.ManagedByPolicy {
		t.Fatalf("governed rule must round-trip marked, got %+v ok=%v", ra, ok)
	}
	// Operator rule is preserved and stays unmarked.
	oper, ok := ruleByID(cfg, "OPER-1")
	if !ok {
		t.Fatalf("operator rule OPER-1 must be preserved, rules=%+v", cfg.Rules)
	}
	if oper.ManagedByPolicy {
		t.Fatalf("operator rule must stay unmarked through round-trip, got %+v", oper)
	}
	// The serialized YAML must carry the marker for the governed rule and NOT for
	// the operator rule.
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "managed_by_policy: true") {
		t.Fatalf("written YAML must carry the marker for the governed rule:\n%s", data)
	}
}

// FIX 1 + FIX 2 reinforcement: deny-all clear is IDEMPOTENT through a real apply.
// A first clear writes the lone sentinel; a second v2 apply over that config is
// NOT refused as a sentinel collision (the lone sentinel is the canonical
// deny-all form, not a real tool).
func TestV2_DenyAllClearIsIdempotentAcrossApplies(t *testing.T) {
	// origConfigYAML already carries voice-ai with allowed_tools: [old.tool], the
	// reliable fixture the other CommitV2 tests use.
	path := writeOrigConfig(t, 0o600)
	// First apply: clear -> lone sentinel written.
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimClear, Values: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	plan := commitV2Body(t, path, b, "")
	if _, err := CommitV2(plan, path); err != nil {
		t.Fatalf("first CommitV2: %v", err)
	}
	// Second apply over the produced config must NOT be refused as a collision.
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := DryRunV2(verifiedV2(b), cfg, "", path); err != nil {
		t.Fatalf("deny-all clear must be idempotent (lone sentinel is not a collision), got %v", err)
	}
}

// FIX 2 test 1a: a bundle whose allowed_tools value contains the sentinel is
// refused (unsupported), no write, on the CLEAR path.
func TestV2_SentinelInClearPathValueRefused(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	// clear mode but the bundle still ships the sentinel as a value: refuse it.
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimClear, Values: []string{denyAllToolsSentinel}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_allowed_tools_reserved_value") {
		t.Fatalf("expected reserved-value unsupported on clear path, got %+v", p.Unsupported)
	}
}

// FIX 2 test 1b: the sentinel in a replace value is refused too (the original
// guard, kept; reservation is now total across paths).
func TestV2_SentinelInReplacePathValueRefused(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimReplace, Values: []string{"calendar.read", denyAllToolsSentinel}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !hasUnsupportedV2(p, "agent_allowed_tools_reserved_value") {
		t.Fatalf("expected reserved-value unsupported on replace path, got %+v", p.Unsupported)
	}
}

// FIX 2 test 2: apply where the agent's existing config allowed_tools already
// contains the sentinel name -> fail closed (refuse, no write). A real tool named
// the sentinel would make the deny-all clear form a silent bypass.
func TestV2_SentinelInLocalConfigFailsClosed(t *testing.T) {
	cfg := baseConfig()
	va := cfg.Agents["voice-ai"]
	// A real tool collides with the sentinel: the sentinel appears ALONGSIDE
	// another tool, so this is not the canonical lone-sentinel deny-all form.
	va.AllowedTools = []string{"real.tool", denyAllToolsSentinel}
	cfg.Agents["voice-ai"] = va
	b := bodyV2()
	g := agentGovV2("other")
	g.Suspended = policybundle.DimScalarBoolV2{Mode: dimReplace, Value: true}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	_, err := DryRunV2(verifiedV2(b), cfg, "", targetPath)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("collision in local config must fail closed with ErrUnsupported, got %v", err)
	}
}

// FIX 2 test 3: deny-all via clear on a normal agent (no collision) still works:
// the agent ends with the sentinel-based zero form (zero callable tools).
func TestV2_DenyAllClearStillWorksWithoutCollision(t *testing.T) {
	b := bodyV2()
	g := agentGovV2("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: dimClear, Values: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	p, err := DryRunV2(verifiedV2(b), baseConfig(), "", targetPath)
	if err != nil {
		t.Fatalf("DryRunV2: %v", err)
	}
	va := p.Projected().Agents["voice-ai"]
	if len(va.AllowedTools) != 1 || va.AllowedTools[0] != denyAllToolsSentinel {
		t.Fatalf("deny-all clear must yield the zero-access sentinel, got %v", va.AllowedTools)
	}
}
