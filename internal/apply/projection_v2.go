package apply

// Order 9A.2: project a verified policy_bundle.v2 onto the local Oktsec config
// with explicit per-dimension modes (unmanaged | replace | clear), an
// anti-widening guard, selector matching, target binding, and no-partial apply.
//
// This is a SEPARATE projector from the v1 DryRun/Commit path: v1 stays
// byte-frozen and behaviorally unchanged. The v2 projector reuses the v1 Plan/
// Change/Unsupported types and the v1 Commit safety protocol (backup + atomic
// replace) by extending the patch coverage in write.go, never by rewriting it.
//
// Dimensions PROJECTED in this PR (the cheap, config-aligned set):
//   - rules (global): enabled/disabled/overrides via DimRulesV2, mode-aware
//   - gateway tools (agent-scoped via selectors): DimGatewayV2 -> AllowedTools
//   - per-agent egress domains: AgentEgressV2 allowed/blocked -> Egress
//   - agent suspension: DimScalarBoolV2 -> Suspended
//   - blocked content categories: DimStringSetV2 -> BlockedContent
//   - scan profile: DimScalarStringV2 -> ScanProfile
//
// Dimensions that FAIL CLOSED (reported unsupported, refuse the apply) when
// governed (mode != unmanaged) but not yet implemented:
//   - body-level egress (fleet/global forward-proxy domain lists)
//   - server governance (require_intent, rate limits)
//   - redaction (Enterprise report concern, but a managed mode is refused so it
//     is never silently dropped)
//   - per-agent acls, tool_policies, tool_constraints, tool_chain_rules, and
//     per-agent egress fields beyond allowed/blocked domains (scope,
//     tool_restrictions, scan_requests/responses, blocked_categories, rate
//     limits, integrations)
//
// Every refusal is fail-closed: a governed dimension this PR does not project,
// a merge mode, an ambiguous selector, a would-widen result, or a scalar clear
// that would widen is added to plan.Unsupported and DryRunV2 returns
// ErrUnsupported. A real apply with any unsupported item writes nothing.

import (
	"fmt"
	"slices"
	"sort"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
)

// DimMode values carried by the v2 signed body. Kept local to apply so the
// projector reads as policy intent, not raw strings.
const (
	dimUnmanaged = "unmanaged"
	dimReplace   = "replace"
	dimClear     = "clear"
)

// PlanV2 is the dry-run result for a v2 bundle. It embeds the v1-shaped header
// plus the assignment/target/sequence binding metadata the operator needs to
// see, and reuses the v1 Change/Unsupported vocabulary. Its JSON shape is the
// stable v2 contract; it extends the v1 Plan shape additively (a v2 consumer
// sees the extra assignment block, a v1 consumer ignores it).
type PlanV2 struct {
	Applied       bool   `json:"applied"`
	DryRun        bool   `json:"dry_run"`
	SchemaVersion string `json:"schema_version"`
	PolicyHash    string `json:"policy_hash"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion string `json:"policy_version"`
	Mode          string `json:"mode"`
	TargetConfig  string `json:"target_config"`

	// Assignment binding the operator and automation branch on.
	AssignmentID string `json:"assignment_id"`
	Scope        string `json:"scope"`
	NodeID       string `json:"node_id"`
	Sequence     int64  `json:"sequence"`
	RollbackOf   string `json:"rollback_of"`
	IssuedAt     string `json:"issued_at"`

	Changes     []ChangeV2    `json:"changes"`
	Unsupported []Unsupported `json:"unsupported"`

	projected *config.Config // computed target; consumed by CommitV2, not serialized
}

// Projected returns the in-memory target config the v2 projection computed.
func (p *PlanV2) Projected() *config.Config { return p.projected }

// ChangeV2 is one concrete edit the v2 projection would make. It extends the v1
// Change with an explicit DimMode label so the operator sees intent (REPLACE vs
// CLEAR) in the plan, which the spec requires for v2.
type ChangeV2 struct {
	Kind      string `json:"kind"`
	DimMode   string `json:"dim_mode"`     // replace | clear (unmanaged never emits a change)
	ID        string `json:"id,omitempty"` // rule id
	Action    string `json:"action,omitempty"`
	Agent     string `json:"agent,omitempty"`
	Count     int    `json:"count,omitempty"`      // list cardinality after the change
	Value     string `json:"value,omitempty"`      // scalar value (scan_profile)
	BoolValue bool   `json:"bool_value,omitempty"` // scalar bool (suspended)
}

// DryRunV2 projects a verified v2 bundle onto a copy of cfg. nodeID is the local
// node identity used for target binding (required when the bundle is node
// scoped; ignored for fleet scope). It writes nothing. It returns:
//   - ErrPolicyTargetMismatch  : node-scoped bundle whose node_id != nodeID
//   - ErrUnsupported           : any dimension this PR cannot safely project
//   - ErrMissingAgent          : a selector names an agent absent from config
//
// Target binding is checked BEFORE projection so a mismatch never produces a
// plan or touches the config. Anti-rollback (sequence) is enforced by the
// command layer against the persisted state file, not here, because it needs
// the on-disk last-applied sequence; DryRunV2 carries the binding fields so the
// command can evaluate it.
func DryRunV2(verified *policybundle.VerifiedBundleV2, cfg *config.Config, nodeID, targetConfig string) (*PlanV2, error) {
	body := verified.Bundle.Policy
	plan := &PlanV2{
		DryRun:        true,
		SchemaVersion: policybundle.SchemaVersionV2,
		PolicyHash:    verified.PolicyHash,
		PolicyID:      body.PolicyID,
		PolicyVersion: body.PolicyVersion,
		Mode:          body.Mode,
		TargetConfig:  targetConfig,
		AssignmentID:  body.Assignment.AssignmentID,
		Scope:         body.Assignment.Target.Scope,
		NodeID:        body.Assignment.Target.NodeID,
		Sequence:      body.Assignment.Sequence,
		RollbackOf:    body.Assignment.RollbackOf,
		IssuedAt:      body.Assignment.IssuedAt,
		Changes:       []ChangeV2{},
		Unsupported:   []Unsupported{},
	}

	// --- Target binding (cheap, decisive, before any projection). A node-scoped
	// bundle applies only on its named node; a fleet-scoped bundle applies
	// anywhere. A self-referential rollback (rollback_of == assignment_id) is
	// nonsensical and is refused here (the verifier left it as a TODO for apply).
	if body.Assignment.RollbackOf != "" && body.Assignment.RollbackOf == body.Assignment.AssignmentID {
		return nil, fmt.Errorf("%w: rollback_of names the assignment itself", ErrPolicyTargetMismatch)
	}
	switch body.Assignment.Target.Scope {
	case "node":
		if nodeID == "" {
			return nil, fmt.Errorf("%w: bundle is node-scoped (node_id %q) but no local node id was provided (pass --node-id)",
				ErrPolicyTargetMismatch, body.Assignment.Target.NodeID)
		}
		if body.Assignment.Target.NodeID != nodeID {
			return nil, fmt.Errorf("%w: bundle targets node %q, this node is %q",
				ErrPolicyTargetMismatch, body.Assignment.Target.NodeID, nodeID)
		}
	case "fleet":
		// applies anywhere
	default:
		// The verifier already closes the scope set; defend anyway.
		return nil, fmt.Errorf("%w: unknown target scope %q", ErrUnsupported, body.Assignment.Target.Scope)
	}

	target, err := cloneConfig(cfg)
	if err != nil {
		return nil, err
	}

	// --- Deny-all sentinel collision (FIX 2, fail closed). The deny-all form for
	// allowed_tools is the reserved sentinel name denyAllToolsSentinel written into
	// the agent's allowlist (Community reads an empty allowlist as "all tools", so
	// zero access must be a non-empty list that matches no real tool). That only
	// works if no REAL tool is ever named denyAllToolsSentinel. If a real tool in
	// the local config carries that name, a deny-all (clear) would still allow it,
	// silently defeating the zero-access representation. So if ANY real tool name in
	// the local config (an agent's existing allowed_tools, or the global gateway
	// allow/deny lists) equals the sentinel, refuse the whole apply with a visible
	// fail-closed error rather than risk a silent deny-all bypass.
	//
	// The bundle-side reservation (a bundle value that contains the sentinel is
	// refused on ALL paths, replace and otherwise) lives in the per-dimension
	// projectors below; this is the LOCAL-config / inventory half.
	//
	// Observed inventory: a node snapshot's observed tool inventory is NOT reachable
	// from this apply context (DryRunV2 takes only the loaded config). The
	// observed-inventory collision check therefore belongs where that inventory is
	// available (the gateway / runtime, which actually sees backend tool names).
	// That runtime guarantee is now enforced: the gateway and stdio proxy
	// special-case config.DenyAllToolsSentinel BEFORE name matching so the sentinel
	// can never execute as a tool, and gateway discovery excludes any backend tool
	// that uses the reserved name. This apply-time check is the LOCAL-config half;
	// the runtime is the inventory half.
	if where := collideToolSentinel(target); where != "" {
		return nil, fmt.Errorf("%w: a real tool in the local config uses the reserved deny-all sentinel name %q (%s); rename that tool before applying a policy",
			ErrUnsupported, denyAllToolsSentinel, where)
	}

	// --- Body-level dimensions that are NOT projected in this PR fail closed
	// when governed. unmanaged is the only "not governed" meaning. ---
	projectRulesV2(plan, target, body)
	// Body-level gateway governs the GLOBAL gateway tool lists, which this PR
	// does not project (per-agent allowed_tools is projected via the agent
	// governance selector instead). A governed body gateway must fail closed so
	// a signed global gateway policy is never silently dropped.
	failClosedIfManaged(plan, "body_gateway", body.Gateway.Mode,
		"global gateway tool lists are not projected by Community apply in this PR (use per-agent allowed_tools governance)")
	failClosedIfManaged(plan, "body_egress", body.Egress.Mode,
		"fleet/global egress domain lists are not projected by Community apply in this PR")
	failClosedIfManaged(plan, "server_governance", body.Governance.Server.Mode,
		"server governance (require_intent, rate limits) is not projected by Community apply in this PR")
	failClosedIfManaged(plan, "redaction", body.Redaction.Mode,
		"redaction is an Enterprise report concern and is not projected onto Community runtime")

	// --- Per-agent governance via selectors. Selector overlap on the SAME
	// dimension fails closed; matched agents are projected. ---
	if err := projectAgentsV2(plan, target, body); err != nil {
		return nil, err // ErrMissingAgent
	}

	// Validate the computed target before returning it.
	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("apply: projected config is invalid: %w", err)
	}
	plan.projected = target

	if len(plan.Unsupported) > 0 {
		return plan, ErrUnsupported
	}
	return plan, nil
}

// failClosedIfManaged records an unsupported entry when a not-yet-projected
// dimension is governed (mode != unmanaged). unmanaged is a silent no-op.
func failClosedIfManaged(plan *PlanV2, kind, mode, detail string) {
	if mode == dimUnmanaged {
		return
	}
	plan.Unsupported = append(plan.Unsupported, Unsupported{Kind: kind, Detail: detail})
}

// projectRulesV2 projects the global rules dimension. unmanaged leaves rules
// untouched. replace governs the enabled/disabled/overrides exactly as v1 does
// (reusing the same severity-default / observe / mapAction semantics) and treats
// the bundle's named set as a HARD CLAIM over the node's governed rule set: any
// pre-existing local rule not named by the bundle is either reaped (if it is a
// stale policy-owned rule, marked managed_by_policy) or blocks the apply closed
// (if its ownership is unknown, i.e. unmarked). clear is not a meaningful rules
// operation here (Community rules are active by default and a config rules entry
// is an override) and there is no enumerated empty form that does not widen, so
// a rules clear fails closed.
func projectRulesV2(plan *PlanV2, target *config.Config, body policybundle.PolicyBodyV2) {
	switch body.Rules.Mode {
	case dimUnmanaged:
		return
	case dimClear:
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "rules_clear_unsupported",
			Detail: "clearing the global rules dimension has no safe Community form (rules are active by default; an empty override set would widen high/critical rules), use replace",
		})
		return
	case dimReplace:
		// fall through
	default:
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "rules_mode_unsupported",
			Detail: fmt.Sprintf("rules.mode %q is not projectable (merge is rejected)", body.Rules.Mode),
		})
		return
	}

	observe := body.Mode == ModeObserve

	idx := make(map[string]int, len(target.Rules))
	for i, ra := range target.Rules {
		idx[ra.ID] = i
	}

	// PREFLIGHT: fail closed on unknown-ownership rules BEFORE any mutation.
	// A v2 replace is a HARD CLAIM that the node's governed rule set equals the
	// signed set, named by the bundle (enabled + overrides keys + disabled). Any
	// EXISTING local rule NOT named and NOT marked managed_by_policy is of unknown
	// provenance: we will not silently keep it (that would leave the node above the
	// signed set) nor blindly delete it (that would destroy operator config). We
	// detect this BEFORE running any upsert/reset so a fail-closed apply leaves the
	// projection byte-unchanged (no partial mutation in plan.Projected or
	// plan.Changes) and DryRunV2 returns ErrUnsupported with no state advance.
	// v1 apply never writes the marker, so a rule v1 wrote is unmarked and BLOCKS
	// here; that is the correct, safe behavior. The operator reconciles by naming
	// the rule in the policy or removing it locally first.
	named := make(map[string]struct{}, len(body.Rules.Enabled)+len(body.Rules.Overrides)+len(body.Rules.Disabled))
	for _, id := range body.Rules.Enabled {
		named[id] = struct{}{}
	}
	for id := range body.Rules.Overrides {
		named[id] = struct{}{}
	}
	for _, id := range body.Rules.Disabled {
		named[id] = struct{}{}
	}
	var unowned []string
	for _, ra := range target.Rules {
		if _, ok := named[ra.ID]; ok {
			continue
		}
		if !ra.ManagedByPolicy {
			unowned = append(unowned, ra.ID)
		}
	}
	if len(unowned) > 0 {
		sort.Strings(unowned)
		for _, id := range unowned {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "rules_replace_unowned_local_rule",
				Detail: fmt.Sprintf("rule %q is a local rule of unknown ownership (not named by the bundle and not marked managed_by_policy); a v2 rules replace claims the node's governed rule set equals the signed set, so it fails closed rather than silently keep or delete it; name %q in the policy or remove it locally first", id, id),
			})
		}
		// Fail closed without mutating the projection: no upsert, no reap.
		return
	}

	// governedWritten records every rule id the bundle's signed desired set writes
	// or marks during this replace (it is "named by the bundle"). It is the
	// authoritative GOVERNED set: after the upserts and resets run, any EXISTING
	// local rule NOT in this set is reconciled against ownership below: a stale
	// policy-owned (marked) rule is reaped, an unmarked rule of unknown ownership
	// fails the apply closed.
	governedWritten := map[string]struct{}{}
	// upsert writes (or updates) a rule id to action and marks it
	// managed_by_policy: this rule is now owned by the signed policy. It records the
	// id in governedWritten so the reap step never removes a rule the bundle just
	// declared.
	upsert := func(id, action string) {
		governedWritten[id] = struct{}{}
		if i, ok := idx[id]; ok {
			scoped := len(target.Rules[i].ApplyToTools) > 0 || len(target.Rules[i].ExemptTools) > 0
			if target.Rules[i].Action == action && !scoped && target.Rules[i].ManagedByPolicy {
				return
			}
			target.Rules[i].Action = action
			target.Rules[i].ApplyToTools = nil
			target.Rules[i].ExemptTools = nil
			target.Rules[i].ManagedByPolicy = true
		} else {
			target.Rules = append(target.Rules, config.RuleAction{ID: id, Action: action, ManagedByPolicy: true})
			idx[id] = len(target.Rules) - 1
		}
		plan.Changes = append(plan.Changes, ChangeV2{Kind: "rule_override", DimMode: dimReplace, ID: id, Action: action})
	}
	// resetToDefault removes a rule override so the rule runs at its severity
	// default. The id is still part of the governed set (the bundle enabled it with
	// no override), so it is recorded in governedWritten and never reaped.
	resetToDefault := func(id string) {
		governedWritten[id] = struct{}{}
		i, ok := idx[id]
		if !ok {
			return
		}
		target.Rules = append(target.Rules[:i], target.Rules[i+1:]...)
		delete(idx, id)
		for j := i; j < len(target.Rules); j++ {
			idx[target.Rules[j].ID] = j
		}
		plan.Changes = append(plan.Changes, ChangeV2{Kind: "rule_reset_default", DimMode: dimReplace, ID: id})
	}

	disabledSet := make(map[string]struct{}, len(body.Rules.Disabled))
	for _, id := range body.Rules.Disabled {
		disabledSet[id] = struct{}{}
	}
	governed := make(map[string]struct{}, len(body.Rules.Enabled)+len(body.Rules.Overrides))
	for _, id := range body.Rules.Enabled {
		governed[id] = struct{}{}
	}
	for id := range body.Rules.Overrides {
		governed[id] = struct{}{}
	}
	active := make([]string, 0, len(governed))
	for id := range governed {
		if _, off := disabledSet[id]; off {
			continue
		}
		active = append(active, id)
	}
	sort.Strings(active)
	for _, id := range active {
		if observe {
			upsert(id, "allow-and-flag")
			continue
		}
		ov, ok := body.Rules.Overrides[id]
		if !ok {
			resetToDefault(id)
			continue
		}
		m, mok := mapAction(ov.Action)
		if !mok {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "rule_override_action",
				Detail: fmt.Sprintf("rule %q has unmappable action %q", id, ov.Action),
			})
			continue
		}
		upsert(id, m)
	}

	disabled := append([]string(nil), body.Rules.Disabled...)
	sort.Strings(disabled)
	for _, id := range disabled {
		upsert(id, "ignore")
	}

	// Reap stale policy-owned rules. The preflight above already failed closed on
	// any unmarked local rule the bundle does not name, so every EXISTING local
	// rule still not in governedWritten here is one a PRIOR policy apply marked
	// managed_by_policy that this bundle no longer declares: reap it (reset to
	// severity default) so the node converges exactly to the signed governed set.
	// We only ever REMOVE rules carrying the marker, so operator-authored config is
	// never deleted by a policy apply. Collect ids first (reaping mutates
	// target.Rules / idx) and process them in deterministic order for a stable plan.
	var reap []string
	for id, i := range idx {
		if _, kept := governedWritten[id]; kept {
			continue
		}
		if target.Rules[i].ManagedByPolicy {
			reap = append(reap, id)
		}
	}
	sort.Strings(reap)
	for _, id := range reap {
		i, ok := idx[id]
		if !ok {
			continue
		}
		target.Rules = append(target.Rules[:i], target.Rules[i+1:]...)
		delete(idx, id)
		for j := i; j < len(target.Rules); j++ {
			idx[target.Rules[j].ID] = j
		}
		plan.Changes = append(plan.Changes, ChangeV2{Kind: "rule_reset_default", DimMode: dimReplace, ID: id})
	}
}

// projectAgentsV2 matches each governance entry to config agents and projects
// the implemented per-agent dimensions. It enforces selector overlap fail-closed
// per dimension. A selector that matches no agent by name is ErrMissingAgent
// (the operator named an agent the config does not have, same contract as v1).
func projectAgentsV2(plan *PlanV2, target *config.Config, body policybundle.PolicyBodyV2) error {
	// dimensionTouched[agentName][dimension] guards selector overlap: two
	// governance entries governing the same dimension of the same agent is
	// ambiguous and fails closed (Phase A rule).
	dimensionTouched := map[string]map[string]bool{}
	mark := func(agentName, dim string) bool {
		m := dimensionTouched[agentName]
		if m == nil {
			m = map[string]bool{}
			dimensionTouched[agentName] = m
		}
		if m[dim] {
			return false
		}
		m[dim] = true
		return true
	}

	for i := range body.Governance.Agents {
		gov := &body.Governance.Agents[i]
		matches, err := matchAgents(plan, target, gov.Selector)
		if err != nil {
			return err
		}
		for _, name := range matches {
			agent := target.Agents[name]

			// Each implemented dimension: guard overlap, then project per mode.
			projectAgentAllowedToolsV2(plan, &agent, name, gov, mark)
			projectAgentEgressV2(plan, target, &agent, name, gov, mark)
			projectAgentSuspendedV2(plan, &agent, name, gov, mark)
			projectAgentBlockedContentV2(plan, &agent, name, gov, mark)
			projectAgentScanProfileV2(plan, &agent, name, gov, mark)

			// Per-agent dimensions NOT implemented in this PR: fail closed when
			// governed. These map onto config but are deferred; never silently
			// ignored.
			failAgentDimIfManaged(plan, name, "acls", gov.ACLs.Mode)
			failAgentDimIfManaged(plan, name, "tool_policies", gov.ToolPolicies.Mode)
			failAgentDimIfManaged(plan, name, "tool_constraints", gov.ToolConstraints.Mode)
			failAgentDimIfManaged(plan, name, "tool_chain_rules", gov.ToolChainRules.Mode)

			target.Agents[name] = agent
		}
	}
	return nil
}

// unknownManagedMode fails closed when a dimension's mode is managed but not
// one this projector acts on (replace/clear). In practice that is "merge"
// (deferred) or any value the verifier somehow let through. unmanaged is
// handled by the caller before this is reached. Returns true when it recorded
// an unsupported entry (the caller must then return without projecting).
func unknownManagedMode(plan *PlanV2, agent, dim, mode string) bool {
	switch mode {
	case dimReplace, dimClear:
		return false
	default:
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_" + dim + "_mode_unsupported",
			Detail: fmt.Sprintf("agent %q dimension %q has mode %q which Community apply does not support (merge is deferred)", agent, dim, mode),
		})
		return true
	}
}

func failAgentDimIfManaged(plan *PlanV2, agent, dim, mode string) {
	if mode == dimUnmanaged {
		return
	}
	plan.Unsupported = append(plan.Unsupported, Unsupported{
		Kind:   "agent_" + dim + "_unsupported",
		Detail: fmt.Sprintf("agent %q dimension %q is governed (mode %q) but not projected by Community apply in this PR", agent, dim, mode),
	})
}

// projectAgentAllowedToolsV2 projects allowed_tools (config.Agent.AllowedTools).
//   - unmanaged: untouched.
//   - replace: set exactly to the bundle values. An EMPTY replace value is a
//     hard error (it would resolve to Community "all tools allowed", a widen),
//     so it is refused. deny-all goes through clear.
//   - clear: the genuine zero-access form. Community reads an empty allowlist as
//     "all", so the zero form is a single sentinel tool that matches nothing.
func projectAgentAllowedToolsV2(plan *PlanV2, agent *config.Agent, name string, gov *policybundle.AgentGovernanceV2, mark func(string, string) bool) {
	mode := gov.AllowedTools.Mode
	if mode == dimUnmanaged {
		return
	}
	if !mark(name, "allowed_tools") {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_allowed_tools_ambiguous_selector",
			Detail: fmt.Sprintf("agent %q allowed_tools governed by more than one selector", name),
		})
		return
	}
	if badMode := unknownManagedMode(plan, name, "allowed_tools", mode); badMode {
		return
	}
	// The deny-all sentinel name is RESERVED on EVERY path, not just replace: any
	// bundle allowed_tools value that contains it is refused (unsupported),
	// regardless of mode. A bundle could otherwise smuggle "deny-all" through a
	// non-clear path, or (under replace) defeat a later clear comparison. clear
	// carries no bundle values, so this guard is a no-op there, but checking
	// unconditionally keeps the reservation total and future-proof.
	if slices.Contains(gov.AllowedTools.Values, denyAllToolsSentinel) {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_allowed_tools_reserved_value",
			Detail: fmt.Sprintf("agent %q allowed_tools value contains the reserved deny-all sentinel %q; use clear for deny-all", name, denyAllToolsSentinel),
		})
		return
	}
	switch mode {
	case dimReplace:
		vals := gov.AllowedTools.Values
		if len(vals) == 0 {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_allowed_tools_empty_replace",
				Detail: fmt.Sprintf("agent %q allowed_tools replace has an empty value, which Community reads as 'all tools' (a widen); use clear for deny-all", name),
			})
			return
		}
		next := append([]string(nil), vals...)
		if !slices.Equal(agent.AllowedTools, next) {
			agent.AllowedTools = next
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_allowed_tools", DimMode: dimReplace, Agent: name, Count: len(next)})
		}
	case dimClear:
		// Genuine zero-access form: a single sentinel that matches no real tool.
		// Community's empty allowlist means "all", so we cannot use []; the
		// sentinel yields zero callable tools without widening.
		zero := []string{denyAllToolsSentinel}
		if !slices.Equal(agent.AllowedTools, zero) {
			agent.AllowedTools = zero
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_allowed_tools", DimMode: dimClear, Agent: name, Count: 0})
		}
	}
}

// denyAllToolsSentinel is the genuine zero-access allowlist value. Community
// treats an empty allowlist as "all tools allowed", so deny-all must be a
// non-empty list that matches no real tool. This name is RESERVED: a bundle
// value containing it is refused on every path (see projectAgentAllowedToolsV2),
// and a real tool in the local config carrying it fails the apply closed (see
// collideToolSentinel), so the sentinel can never be a real tool and the clear
// (deny-all) form can never be defeated. The canonical name lives in
// internal/config so the runtime enforcement (gateway + stdio proxy) and
// discovery rejection share one source of truth with the apply projector.
const denyAllToolsSentinel = config.DenyAllToolsSentinel

// collideToolSentinel returns a non-empty location description when a REAL tool
// name in the local config equals the reserved deny-all sentinel. The only tool
// names the config itself can express are each agent's allowed_tools (the gateway
// has no static tool list in config: it discovers backend tool names at runtime,
// which is the observed-inventory check that lives in the gateway, not here). A
// collision means the sentinel-based deny-all form would not actually deny that
// tool, so the caller fails the apply closed rather than risk a silent deny-all
// bypass.
//
// The CANONICAL deny-all form an apply itself writes is an allowlist of EXACTLY
// the lone sentinel ([sentinel]); that is the zero-access representation, not a
// real tool, so it is NOT a collision. Treating it as one would make a clear
// non-idempotent (reapplying the same deny-all bundle, or any later v2 apply,
// would be refused because the config it produced still carries the sentinel). A
// genuine collision is the sentinel appearing ALONGSIDE other tool names: an
// allowlist where the sentinel is present but the list is not exactly [sentinel].
// Agents are scanned in sorted order so the reported location is deterministic.
func collideToolSentinel(cfg *config.Config) string {
	names := make([]string, 0, len(cfg.Agents))
	for name := range cfg.Agents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tools := cfg.Agents[name].AllowedTools
		if !slices.Contains(tools, denyAllToolsSentinel) {
			continue
		}
		// Lone sentinel == the canonical deny-all form this apply writes; allowed.
		if len(tools) == 1 {
			continue
		}
		return fmt.Sprintf("agent %q allowed_tools", name)
	}
	return ""
}

// projectAgentEgressV2 projects the per-agent egress allowed/blocked domains.
// Only those two fields are implemented; any OTHER governed egress field (scope,
// tool_restrictions, scan_requests/responses, blocked_categories, rate limits,
// integrations) makes the whole egress dimension fail closed, because projecting
// only part of a governed egress policy could change its meaning.
//   - unmanaged: untouched.
//   - replace: allowed/blocked set exactly. An empty allowed under replace is
//     a hard error (empty allowed_domains unions with global/presets and does
//     not restrict, i.e. it does not express deny-all here) -> use clear.
//   - clear: zero allowed domains (the restrictive empty form for this agent).
func projectAgentEgressV2(plan *PlanV2, target *config.Config, agent *config.Agent, name string, gov *policybundle.AgentGovernanceV2, mark func(string, string) bool) {
	eg := gov.Egress
	if eg.Mode == dimUnmanaged {
		return
	}
	if !mark(name, "egress") {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_egress_ambiguous_selector",
			Detail: fmt.Sprintf("agent %q egress governed by more than one selector", name),
		})
		return
	}
	if unknownManagedMode(plan, name, "egress", eg.Mode) {
		return
	}
	// Reject if any unimplemented egress sub-field is set, so a governed egress
	// policy is never partially projected.
	if eg.Scope != "" || len(eg.ToolRestrictions) > 0 || eg.ScanRequests != "unset" ||
		eg.ScanResponses != "unset" || len(eg.BlockedCategories) > 0 ||
		eg.RateLimit != 0 || eg.RateWindow != 0 || len(eg.Integrations) > 0 {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_egress_unsupported_fields",
			Detail: fmt.Sprintf("agent %q egress sets fields beyond allowed/blocked domains (scope/tool_restrictions/scan_*/blocked_categories/rate/integrations) which Community apply does not project in this PR", name),
		})
		return
	}

	switch eg.Mode {
	case dimReplace:
		if len(eg.AllowedDomains) == 0 {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_egress_empty_replace",
				Detail: fmt.Sprintf("agent %q egress replace has empty allowed_domains, which does not restrict (it unions with global/preset domains); use clear for zero egress", name),
			})
			return
		}
		if slices.Contains(eg.AllowedDomains, denyAllDomainsSentinel) {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_egress_reserved_value",
				Detail: fmt.Sprintf("agent %q egress replace contains the reserved zero-egress sentinel %q; use clear for zero egress", name, denyAllDomainsSentinel),
			})
			return
		}
		// Additive-source guard (mirrors v1): the egress resolver UNIONS the
		// agent's allowed_domains with the global forward_proxy allowlist and any
		// integration presets the agent already carries. Setting the agent's list
		// to the bundle's only equals the bundle's intended restriction when those
		// other sources add nothing outside it. If a source additively permits a
		// domain the policy excludes (and the policy/agent does not also deny it),
		// the restriction is not expressible here, so refuse rather than report a
		// success that still permits that domain. (blocked is checked before
		// allowed at runtime, so a domain the policy or agent denies is not a
		// widener.)
		if outside := egressAdditiveWideners(target, agent, eg); len(outside) > 0 {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_egress_allowed_not_restrictable",
				Detail: fmt.Sprintf("agent %q egress.allowed_domains cannot restrict it: a global forward_proxy allowlist or the agent's integration presets additively permit domain(s) outside the policy: %v", name, outside),
			})
			return
		}
		ensureEgress(agent)
		if !slices.Equal(agent.Egress.AllowedDomains, eg.AllowedDomains) {
			agent.Egress.AllowedDomains = append([]string(nil), eg.AllowedDomains...)
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_egress_allowed_domains", DimMode: dimReplace, Agent: name, Count: len(eg.AllowedDomains)})
		}
		// blocked under replace is additive-faithful (deny is monotonic).
		if !slices.Equal(agent.Egress.BlockedDomains, eg.BlockedDomains) {
			agent.Egress.BlockedDomains = append([]string(nil), eg.BlockedDomains...)
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_egress_denied_domains", DimMode: dimReplace, Agent: name, Count: len(eg.BlockedDomains)})
		}
	case dimClear:
		// Zero egress: setting the agent's allowed_domains to the sentinel only
		// produces genuine zero egress when no OTHER source still permits a
		// domain. The runtime egress resolver unions the agent allowlist with the
		// global forward_proxy allowlist and the agent's integration presets, and
		// a per-tool egress.tool_restrictions entry bypasses the allowlist
		// entirely. If any of those additive sources is present, the sentinel does
		// not achieve deny-all, so refuse rather than report a misleading clear.
		// (egressAdditiveWideners with an empty policy set treats EVERY additive
		// domain as outside, and flags a non-empty scope / tool_restrictions.)
		if outside := egressAdditiveWideners(target, agent, policybundle.DimAgentEgressV2{}); len(outside) > 0 {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_egress_clear_not_zeroable",
				Detail: fmt.Sprintf("agent %q egress clear cannot yield zero egress: a global forward_proxy allowlist, integration preset, scope, or tool restriction additively permits domain(s): %v; remove those sources first", name, outside),
			})
			return
		}
		ensureEgress(agent)
		// No additive source remains, so the deny-all sentinel (matches nothing)
		// plus an empty blocked list yields zero permitted domains for this agent.
		zero := []string{denyAllDomainsSentinel}
		if !slices.Equal(agent.Egress.AllowedDomains, zero) || len(agent.Egress.BlockedDomains) != 0 {
			agent.Egress.AllowedDomains = zero
			agent.Egress.BlockedDomains = nil
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_egress_allowed_domains", DimMode: dimClear, Agent: name, Count: 0})
		}
	}
}

// denyAllDomainsSentinel is the genuine zero-egress allowed-domain value for an
// agent. An empty allowed_domains list unions with global/preset domains, so it
// does not deny; a reserved domain that matches no real host yields zero egress.
const denyAllDomainsSentinel = "deny-all.invalid"

// projectAgentSuspendedV2 projects suspension.
//   - unmanaged: untouched.
//   - replace: set exactly to the bundle bool.
//   - clear: FORBIDDEN. clear -> false un-suspends, which widens safety posture.
//     Use replace with the explicit value.
func projectAgentSuspendedV2(plan *PlanV2, agent *config.Agent, name string, gov *policybundle.AgentGovernanceV2, mark func(string, string) bool) {
	mode := gov.Suspended.Mode
	if mode == dimUnmanaged {
		return
	}
	if !mark(name, "suspended") {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_suspended_ambiguous_selector",
			Detail: fmt.Sprintf("agent %q suspended governed by more than one selector", name),
		})
		return
	}
	if unknownManagedMode(plan, name, "suspended", mode) {
		return
	}
	switch mode {
	case dimReplace:
		if agent.Suspended != gov.Suspended.Value {
			agent.Suspended = gov.Suspended.Value
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_suspended", DimMode: dimReplace, Agent: name, BoolValue: gov.Suspended.Value})
		}
	case dimClear:
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_suspended_clear_widens",
			Detail: fmt.Sprintf("agent %q suspended clear resets to false (un-suspends), which widens safety posture; use replace with an explicit value", name),
		})
	}
}

// projectAgentBlockedContentV2 projects blocked content categories.
//   - unmanaged: untouched.
//   - replace: set exactly. An empty replace is a hard error (use clear to mean
//     "block no categories"); empty under replace must never be a silent no-op.
//   - clear: empty list (block no categories). This is the safe, narrowing
//     empty form for a denylist: it never adds capability.
func projectAgentBlockedContentV2(plan *PlanV2, agent *config.Agent, name string, gov *policybundle.AgentGovernanceV2, mark func(string, string) bool) {
	mode := gov.BlockedContent.Mode
	if mode == dimUnmanaged {
		return
	}
	if !mark(name, "blocked_content") {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_blocked_content_ambiguous_selector",
			Detail: fmt.Sprintf("agent %q blocked_content governed by more than one selector", name),
		})
		return
	}
	if unknownManagedMode(plan, name, "blocked_content", mode) {
		return
	}
	switch mode {
	case dimReplace:
		vals := gov.BlockedContent.Values
		if len(vals) == 0 {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_blocked_content_empty_replace",
				Detail: fmt.Sprintf("agent %q blocked_content replace is empty; use clear to mean 'block no categories' (empty replace is never a silent no-op)", name),
			})
			return
		}
		next := append([]string(nil), vals...)
		if !slices.Equal(agent.BlockedContent, next) {
			agent.BlockedContent = next
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_blocked_content", DimMode: dimReplace, Agent: name, Count: len(next)})
		}
	case dimClear:
		if len(agent.BlockedContent) != 0 {
			agent.BlockedContent = []string{}
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_blocked_content", DimMode: dimClear, Agent: name, Count: 0})
		}
	}
}

// projectAgentScanProfileV2 projects scan_profile.
//   - unmanaged: untouched.
//   - replace: set exactly. The value must be a Community-valid profile (the
//     verifier already closes this, but the projector re-checks defensively and
//     refuses an empty replace, which would reset to the strict default and is
//     ambiguous with clear).
//   - clear: FORBIDDEN. clear -> "" resets scan_profile to the strict default;
//     since a stricter-than-current profile cannot be guaranteed (e.g. current
//     is already strict, target default is strict -> fine, but current minimal
//     -> strict is a tightening yet current strict -> default strict is a no-op,
//     and resetting away from a stricter explicit profile could widen), we
//     forbid clear and require an explicit replace value. This matches the
//     scalar-clear-widens rule.
func projectAgentScanProfileV2(plan *PlanV2, agent *config.Agent, name string, gov *policybundle.AgentGovernanceV2, mark func(string, string) bool) {
	mode := gov.ScanProfile.Mode
	if mode == dimUnmanaged {
		return
	}
	if !mark(name, "scan_profile") {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_scan_profile_ambiguous_selector",
			Detail: fmt.Sprintf("agent %q scan_profile governed by more than one selector", name),
		})
		return
	}
	if unknownManagedMode(plan, name, "scan_profile", mode) {
		return
	}
	switch mode {
	case dimReplace:
		v := gov.ScanProfile.Value
		switch v {
		case config.ScanProfileStrict, config.ScanProfileContentAware, config.ScanProfileMinimal:
			// ok
		default:
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_scan_profile_invalid",
				Detail: fmt.Sprintf("agent %q scan_profile replace value %q is not a Community profile (strict|content-aware|minimal); empty is not allowed under replace", name, v),
			})
			return
		}
		if agent.ScanProfile != v {
			agent.ScanProfile = v
			plan.Changes = append(plan.Changes, ChangeV2{Kind: "agent_scan_profile", DimMode: dimReplace, Agent: name, Value: v})
		}
	case dimClear:
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_scan_profile_clear_unsupported",
			Detail: fmt.Sprintf("agent %q scan_profile clear resets to the default profile and may widen scanning posture; use replace with an explicit value", name),
		})
	}
}

func ensureEgress(agent *config.Agent) {
	if agent.Egress == nil {
		agent.Egress = &config.EgressPolicy{}
	}
}

// egressAdditiveWideners returns the domains an additive egress source (the
// global forward_proxy allowlist or the agent's integration presets) would
// still permit but the bundle's replace allowlist excludes, after accounting
// for deny lists (blocked wins over allowed at runtime). An empty result means
// the bundle's allowlist faithfully restricts the agent. A non-empty agent
// egress.scope is itself an additive source the projector cannot reason about,
// so it is reported as a single opaque widener "(scope)". This mirrors v1's
// agent_egress_allowed_not_restrictable check.
func egressAdditiveWideners(target *config.Config, agent *config.Agent, eg policybundle.DimAgentEgressV2) []string {
	policySet := make(map[string]struct{}, len(eg.AllowedDomains))
	for _, d := range eg.AllowedDomains {
		policySet[d] = struct{}{}
	}
	// Effective deny set = bundle denied ∪ global blocked. A denied domain is
	// blocked regardless of any additive allow, so it is not a widener.
	denySet := make(map[string]struct{})
	for _, d := range target.ForwardProxy.BlockedDomains {
		denySet[d] = struct{}{}
	}
	for _, d := range eg.BlockedDomains {
		denySet[d] = struct{}{}
	}

	var additive []string
	additive = append(additive, target.ForwardProxy.AllowedDomains...)
	if agent.Egress != nil && len(agent.Egress.Integrations) > 0 {
		additive = append(additive, config.ResolveIntegrationDomains(agent.Egress.Integrations)...)
	}

	var outside []string
	seen := map[string]struct{}{}
	for _, d := range additive {
		if _, ok := policySet[d]; ok {
			continue // within the policy allowlist
		}
		if _, denied := denySet[d]; denied {
			continue // blocked wins
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		outside = append(outside, d)
	}
	// A pre-existing agent egress.scope opens internal/named domains the
	// projector cannot enumerate; treat it as a widener so a governed restrict
	// fails closed rather than silently leaving the scope in place.
	if agent.Egress != nil && agent.Egress.Scope != "" {
		outside = append(outside, "(scope)")
	}
	// A pre-existing per-tool egress.tool_restrictions entry bypasses the
	// resolved AllowedDomains (the runtime checks ToolDomainAllowed separately),
	// so a restrict that only rewrites allowed_domains leaves those tool-scoped
	// domains reachable. The projector does not rewrite tool_restrictions, so
	// treat any existing entry as a widener and fail closed.
	if agent.Egress != nil && len(agent.Egress.ToolRestrictions) > 0 {
		outside = append(outside, "(tool_restrictions)")
	}
	// Pre-existing scan overrides and blocked categories on the agent are part of
	// its egress posture that the projector does NOT rewrite when it governs only
	// the domain lists. Leaving them in place means the projected egress policy is
	// a mix of the signed domain lists and stale local fields, so the result is
	// not faithfully the signed egress dimension. Fail closed when any are present
	// so the operator removes them first rather than getting a partial projection.
	if agent.Egress != nil {
		if agent.Egress.ScanRequests != nil || agent.Egress.ScanResponses != nil {
			outside = append(outside, "(scan_overrides)")
		}
		if len(agent.Egress.BlockedCategories) > 0 {
			outside = append(outside, "(blocked_categories)")
		}
		if agent.Egress.RateLimit != 0 || agent.Egress.RateWindow != 0 {
			outside = append(outside, "(rate_limit)")
		}
	}
	return outside
}

// matchAgents resolves a selector to config agent names. The verifier
// (validatePolicySchemaV2) already requires selector.name to be non-empty for
// every governance entry, so the production apply path never sees a label-only
// selector; this projector enforces the same contract defensively. A name
// selector is an exact match and the agent MUST exist (ErrMissingAgent
// otherwise, mirroring v1). When labels are also present, the named agent must
// additionally carry every label (label k=v matches a config Tags entry "k=v",
// or a bare tag "k" when v is empty); a named agent that lacks a required label
// matches nothing (not an error). A label-only selector (empty name) is itself
// unsupported and reported, never silently treated as "match all".
func matchAgents(plan *PlanV2, cfg *config.Config, sel policybundle.SelectorV2) ([]string, error) {
	if sel.Name == "" {
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "agent_selector_name_required",
			Detail: "a governance selector with no name is not supported by Community apply; name the agent the entry governs (labels narrow a named selector)",
		})
		return nil, nil
	}
	agent, ok := cfg.Agents[sel.Name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrMissingAgent, sel.Name)
	}
	if !agentHasLabels(agent, sel.Labels) {
		// Named agent that does not carry the required labels matches nothing.
		return nil, nil
	}
	return []string{sel.Name}, nil
}

// agentHasLabels reports whether agent carries every required label. A label
// "k=v" must appear verbatim in Tags, or "k" alone when the required value is
// empty. The matching is deliberately simple and explicit.
func agentHasLabels(agent config.Agent, labels map[string]string) bool {
	if len(labels) == 0 {
		return true
	}
	have := make(map[string]struct{}, len(agent.Tags))
	for _, t := range agent.Tags {
		have[t] = struct{}{}
	}
	for k, v := range labels {
		want := k
		if v != "" {
			want = k + "=" + v
		}
		if _, ok := have[want]; !ok {
			return false
		}
	}
	return true
}
