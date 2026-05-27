// Package apply projects a verified policy_bundle.v1 onto the local Oktsec
// runtime config. Order 7A.2 ships the dry-run projection only: it computes
// the target config in memory, validates it, and reports the exact changes
// without writing anything. The safe in-place write (backup + atomic
// rename) lands in a later slice.
//
// Scope of the supported subset (post-6E spec §7-§9): rules are global
// (enabled / disabled / overrides); gateway tools and egress domains are
// scoped to a single explicitly-selected --agent. Semantics outside this
// subset that would change runtime meaning are reported as unsupported and
// refused by default — never silently applied or ignored.
//
// The signed bundle carries the Enterprise policy vocabulary
// (flag/quarantine/block); the Enterprise→Community action mapping happens
// here, at projection time, NOT in the bundle.
package apply

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
	"gopkg.in/yaml.v3"
)

// Mode values carried by the signed policy body.
const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
)

// Sentinels callers branch on.
var (
	// ErrMissingAgent: the --agent named is not declared in the config.
	ErrMissingAgent = errors.New("apply: target agent not found in config")
	// ErrUnsupported: the bundle declares supported-model semantics the
	// narrow apply projection cannot express. The returned Plan still lists
	// them under Unsupported; the caller refuses by default.
	ErrUnsupported = errors.New("apply: bundle contains semantics not supported by the narrow apply projection")
)

// mapAction maps an Enterprise override action to a Community rule action.
// Returns ok=false for an action outside the Enterprise vocabulary (a
// verified bundle never carries one, but the projection refuses rather than
// silently mis-mapping).
func mapAction(enterprise string) (string, bool) {
	switch enterprise {
	case "flag":
		return "allow-and-flag", true
	case "quarantine":
		return "quarantine", true
	case "block":
		return "block", true
	default:
		return "", false
	}
}

// Change is one concrete edit the projection would make to the config.
type Change struct {
	Kind   string `json:"kind"`
	ID     string `json:"id,omitempty"`
	Action string `json:"action,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Count  int    `json:"count,omitempty"`
}

// Unsupported is one supported-model value the narrow projection refuses.
type Unsupported struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Plan is the dry-run result. Its JSON shape is the stable contract.
type Plan struct {
	Applied       bool          `json:"applied"`
	DryRun        bool          `json:"dry_run"`
	PolicyHash    string        `json:"policy_hash"`
	PolicyID      string        `json:"policy_id"`
	PolicyVersion string        `json:"policy_version"`
	Mode          string        `json:"mode"`
	TargetConfig  string        `json:"target_config"`
	Agent         string        `json:"agent"`
	Changes       []Change      `json:"changes"`
	Unsupported   []Unsupported `json:"unsupported"`

	projected *config.Config // computed target config; used by a later write slice, not serialized
}

// Projected returns the in-memory target config the projection computed.
func (p *Plan) Projected() *config.Config { return p.projected }

// DryRun projects a verified bundle's supported subset onto a copy of cfg,
// scoped to agentName, writing nothing. Rules are global; gateway tools and
// egress are scoped to the selected agent. The returned Plan always reflects
// what would change; DryRun returns ErrUnsupported when the bundle declares
// semantics the narrow projection cannot express (refuse-by-default), and
// ErrMissingAgent when the agent is not in the config.
func DryRun(verified *policybundle.VerifiedBundle, cfg *config.Config, agentName, targetConfig string) (*Plan, error) {
	body := verified.Bundle.Policy
	plan := &Plan{
		DryRun:        true,
		PolicyHash:    verified.PolicyHash,
		PolicyID:      body.PolicyID,
		PolicyVersion: body.PolicyVersion,
		Mode:          body.Mode,
		TargetConfig:  targetConfig,
		Agent:         agentName,
		Changes:       []Change{},
		Unsupported:   []Unsupported{},
	}

	// Deep-copy so the projection never mutates the loaded config; unrelated
	// fields are carried over verbatim and preserved in the target.
	target, err := cloneConfig(cfg)
	if err != nil {
		return nil, err
	}

	agent, ok := target.Agents[agentName]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrMissingAgent, agentName)
	}

	observe := body.Mode == ModeObserve

	// --- Rules (global). Upsert by ID so existing rules not named by the
	// policy are preserved, and an updated rule keeps its other fields
	// (severity, notify, ...) while only its action changes. ---
	idx := make(map[string]int, len(target.Rules))
	for i, ra := range target.Rules {
		idx[ra.ID] = i
	}
	// upsert sets a policy-owned rule's action. Policy rules are GLOBAL: the
	// signed bundle carries no per-tool rule scoping, so an existing
	// tool-scoped override (apply_to_tools / exempt_tools) must be widened to
	// global — otherwise a policy that blocks a rule would silently stay
	// limited to the previously-scoped tools. Widening is itself a change even
	// when the action already matches. A dry-run reports exact diffs, so a
	// rule already global on this action shows none.
	upsert := func(id, action string) {
		if i, ok := idx[id]; ok {
			scoped := len(target.Rules[i].ApplyToTools) > 0 || len(target.Rules[i].ExemptTools) > 0
			if target.Rules[i].Action == action && !scoped {
				return // already global on policy — no change
			}
			target.Rules[i].Action = action
			target.Rules[i].ApplyToTools = nil
			target.Rules[i].ExemptTools = nil
		} else {
			target.Rules = append(target.Rules, config.RuleAction{ID: id, Action: action})
			idx[id] = len(target.Rules) - 1
		}
		plan.Changes = append(plan.Changes, Change{Kind: "rule_override", ID: id, Action: action})
	}

	// resetToDefault restores a rule to its severity-based default by removing
	// any local override. Community rules are active by default, so "enabled"
	// without an override means "enforce at the rule's severity default" — and
	// the runtime treats a config.rules entry as an override, so leaving (or
	// adding) an allow-and-flag entry would WEAKEN a high/critical rule instead
	// of enabling it. Removing a local override is a change; no local override
	// is already at default and a no-op.
	resetToDefault := func(id string) {
		i, ok := idx[id]
		if !ok {
			return
		}
		target.Rules = append(target.Rules[:i], target.Rules[i+1:]...)
		delete(idx, id)
		for j := i; j < len(target.Rules); j++ {
			idx[target.Rules[j].ID] = j
		}
		plan.Changes = append(plan.Changes, Change{Kind: "rule_reset_default", ID: id})
	}

	enabled := append([]string(nil), body.Rules.Enabled...)
	sort.Strings(enabled)
	for _, id := range enabled {
		// Observe mode forces every enabled/overridden rule down to
		// allow-and-flag (signal without block/quarantine) — the explicit,
		// intended downgrade of observe.
		if observe {
			upsert(id, "allow-and-flag")
			continue
		}
		// Enforce mode: an explicit override sets the action; without one the
		// rule runs at its severity default (reset any weakening local override).
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

	// --- Gateway tools (agent-scoped). The narrow projection is additive
	// scoping: a non-empty allowlist replaces the agent's tools (a change only
	// when it actually differs). An empty list means "this policy does not
	// govern tools" — NOT "clear the allowlist". Canonical bundles always
	// carry [] for ungoverned dimensions, so treating empty as a clear would
	// make a rules-only policy silently wipe every agent's tools. Removal is a
	// distinct semantic the bundle cannot signal and the projection does not
	// express. ---
	switch {
	case len(body.Gateway.ToolsAllowed) > 0:
		if !slices.Equal(agent.AllowedTools, body.Gateway.ToolsAllowed) {
			agent.AllowedTools = append([]string(nil), body.Gateway.ToolsAllowed...)
			plan.Changes = append(plan.Changes, Change{
				Kind: "agent_allowed_tools", Agent: agentName, Count: len(agent.AllowedTools)})
		}
	case len(body.Gateway.ToolsDenied) > 0:
		// Community gateway control is an allowlist, not a per-agent denylist
		// over an unknown tool universe; tools_denied without tools_allowed
		// cannot be expressed.
		plan.Unsupported = append(plan.Unsupported, Unsupported{
			Kind:   "gateway_tools_denied_without_allowlist",
			Detail: "gateway.tools_denied has no gateway.tools_allowed to project onto a Community agent allowlist",
		})
	}

	// --- Egress (agent-scoped). Same additive-scoping rule as gateway tools:
	// a non-empty domain list replaces the agent's (change only on a real
	// diff); an empty list is "not governed", never a clear. ---
	var curAllowed, curDenied []string
	if agent.Egress != nil {
		curAllowed, curDenied = agent.Egress.AllowedDomains, agent.Egress.BlockedDomains
	}

	// The egress resolver UNIONS an agent's allowed_domains with the global
	// forward_proxy allowlist and any integration presets, so a per-agent
	// allowlist can only RESTRICT when no wider allow-source exists. With one
	// present, the bundle's intended restriction can't be expressed here —
	// refuse rather than emit a config that still permits excluded domains.
	// (Denied domains are monotonic: a deny is additive and always faithful.)
	if len(body.Egress.DomainsAllowed) > 0 {
		widened := len(target.ForwardProxy.AllowedDomains) > 0 ||
			(agent.Egress != nil && len(agent.Egress.Integrations) > 0)
		if widened {
			plan.Unsupported = append(plan.Unsupported, Unsupported{
				Kind:   "agent_egress_allowed_not_restrictable",
				Detail: "egress.domains_allowed cannot restrict the agent: a global forward_proxy allowlist or integration preset widens the effective allowlist additively",
			})
			body.Egress.DomainsAllowed = nil // do not emit a misleading change
		}
	}

	allowedChange := len(body.Egress.DomainsAllowed) > 0 && !slices.Equal(curAllowed, body.Egress.DomainsAllowed)
	deniedChange := len(body.Egress.DomainsDenied) > 0 && !slices.Equal(curDenied, body.Egress.DomainsDenied)
	if allowedChange || deniedChange {
		if agent.Egress == nil {
			agent.Egress = &config.EgressPolicy{}
		}
		if allowedChange {
			agent.Egress.AllowedDomains = append([]string(nil), body.Egress.DomainsAllowed...)
			plan.Changes = append(plan.Changes, Change{
				Kind: "agent_egress_allowed_domains", Agent: agentName, Count: len(agent.Egress.AllowedDomains)})
		}
		if deniedChange {
			agent.Egress.BlockedDomains = append([]string(nil), body.Egress.DomainsDenied...)
			plan.Changes = append(plan.Changes, Change{
				Kind: "agent_egress_denied_domains", Agent: agentName, Count: len(agent.Egress.BlockedDomains)})
		}
	}

	target.Agents[agentName] = agent

	// redaction.level and metadata are Enterprise report/display + audit
	// concerns, not Community runtime settings — intentionally not projected,
	// and NOT "unsupported": they do not change runtime meaning here.

	// Validate the computed target (the spec's "validate target config").
	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("apply: projected config is invalid: %w", err)
	}
	plan.projected = target

	if len(plan.Unsupported) > 0 {
		return plan, ErrUnsupported
	}
	return plan, nil
}

// cloneConfig deep-copies via a YAML round-trip. Config is entirely
// yaml-tagged exported fields, so the clone is faithful and lets the
// projection mutate freely without touching the caller's config.
func cloneConfig(cfg *config.Config) (*config.Config, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("clone config: %w", err)
	}
	var out config.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("clone config: %w", err)
	}
	return &out, nil
}
