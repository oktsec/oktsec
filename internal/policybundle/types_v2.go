package policybundle

// Frozen constants of the policy_bundle.v2 signing contract. These sit
// ALONGSIDE the v1 constants and never reuse or modify them. A change to any
// of these is a v2 contract change: it must be matched on the signing side,
// and the vendored v2 fixture must be regenerated. Drift here surfaces as a
// broken signature on every v2 bundle. SignatureAlg is shared with v1 and is
// not redeclared.
const (
	SchemaVersionV2    = "policy_bundle.v2"
	BundleVersionV2    = 2
	CanonicalizationV2 = "oktsec-policy-v2-typed-utc-json"
)

// PolicyBundleV2 is the signed JSON artifact for the v2 governance contract:
// the outer envelope carries the declared hash and the signature; the inner
// PolicyBodyV2 is the signed content. The envelope shape mirrors v1 so the
// same signature block layout is reused; only the body and the bound
// assignment metadata differ.
type PolicyBundleV2 struct {
	SchemaVersion    string          `json:"schema_version"`
	BundleVersion    int             `json:"bundle_version"`
	PolicyHash       string          `json:"policy_hash"`
	Canonicalization string          `json:"canonicalization"`
	Policy           PolicyBodyV2    `json:"policy"`
	Signature        PolicySignature `json:"signature"`
}

// PolicyBodyV2 is the v2 content covered by policy_hash and the Ed25519
// signature. Field order IS the canonical projection order: the signed bytes
// are produced by encoding this struct exactly as declared. The FULL
// governance surface is defined now, even though apply/projection is 9A.2 -
// the hash must cover the entire surface from day one, or a later PR adding a
// field would change the canonical body and break the pinned fixture. Never
// reorder these fields or change a json tag without changing CanonicalizationV2
// and regenerating the fixture.
type PolicyBodyV2 struct {
	PolicyID      string         `json:"policy_id"`
	PolicyVersion string         `json:"policy_version"`
	Mode          string         `json:"mode"` // "enforce" | "observe", bundle-wide (as v1)
	Assignment    AssignmentV2   `json:"assignment"`
	Rules         DimRulesV2     `json:"rules"`
	Gateway       DimGatewayV2   `json:"gateway"`
	Egress        DimEgressV2    `json:"egress"`
	Governance    GovernanceV2   `json:"governance"`
	Redaction     DimRedactionV2 `json:"redaction"`
	Metadata      PolicyMetadata `json:"metadata"` // reuse v1 shape
}

// AssignmentV2 binds the bundle to a target and carries anti-rollback
// metadata. Every field here is folded into the signing payload (not just the
// body hash) so a store cannot rewrite the target, sequence, or issued_at of
// a signed bundle without breaking the signature.
type AssignmentV2 struct {
	AssignmentID string   `json:"assignment_id"`
	Target       TargetV2 `json:"target"`
	IssuedAt     string   `json:"issued_at"` // canonical UTC timestamp
	Sequence     int64    `json:"sequence"`  // base-10, >= 1
	RollbackOf   string   `json:"rollback_of"`
}

// TargetV2 binds an assignment to a scope. scope is "fleet" or "node";
// node_id is the node it targets (required, non-empty) for a node assignment,
// and MUST be "" for a fleet-wide assignment, so a signed bundle binds to
// exactly one unambiguous target (enforced by the verifier).
type TargetV2 struct {
	Scope  string `json:"scope"`
	NodeID string `json:"node_id"`
}

// DimRulesV2 wraps the v1 rule-ID layer with a dimension mode. Overrides keys
// map a rule id to its action; map keys serialize alphabetically under
// encoding/json, so the canonical bytes are deterministic without explicit
// sorting (verified by test).
type DimRulesV2 struct {
	Mode      string                        `json:"mode"`
	Enabled   []string                      `json:"enabled"`
	Disabled  []string                      `json:"disabled"`
	Overrides map[string]PolicyRuleOverride `json:"overrides"` // reuse v1 override shape
}

type DimGatewayV2 struct {
	Mode         string   `json:"mode"`
	ToolsAllowed []string `json:"tools_allowed"`
	ToolsDenied  []string `json:"tools_denied"`
}

// DimEgressV2 is the FLEET/GLOBAL egress dimension on the body: the
// gateway-wide domain allow/deny lists (config.ForwardProxy global scope). It
// is intentionally NOT the rich per-agent egress policy. Per-agent egress lives
// on AgentGovernanceV2.Egress (DimAgentEgressV2) and mirrors
// config.EgressPolicy field-for-field. Both scopes are kept on purpose: this
// one governs the global forward-proxy domain lists, the per-agent one governs a
// single agent's outbound controls (config.Agent.Egress). They are different
// scopes and must not be collapsed.
type DimEgressV2 struct {
	Mode           string   `json:"mode"`
	DomainsAllowed []string `json:"domains_allowed"`
	DomainsDenied  []string `json:"domains_denied"`
}

// DimRedactionV2 carries the redaction dimension mode plus the level. level
// is "full" | "analyst" | "external", as v1.
type DimRedactionV2 struct {
	Mode  string `json:"mode"`
	Level string `json:"level"`
}

// GovernanceV2 is the full per-agent governance surface. server is the
// server-level governance dimension; agents is the ordered list of per-agent
// governance entries (declaration order in the JSON array IS the canonical
// order - it is hashed as authored).
type GovernanceV2 struct {
	Server ServerGovernanceV2  `json:"server"`
	Agents []AgentGovernanceV2 `json:"agents"`
}

// ServerGovernanceV2 mirrors the small set of server-level proxy settings that
// a policy bundle can govern (see config.ServerConfig). It is intentionally
// minimal but fully typed so canonicalization is deterministic. require_intent
// and the rate-limit pair are the governable knobs; apply logic is 9A.2.
type ServerGovernanceV2 struct {
	Mode            string `json:"mode"`
	RequireIntent   bool   `json:"require_intent"`
	RateLimitMax    int64  `json:"rate_limit_max"`      // max messages per window (config.RateLimitConfig)
	RateLimitWindow int64  `json:"rate_limit_window_s"` // window seconds
}

// AgentGovernanceV2 is the per-agent governance surface. Every Community
// per-agent config knob (config.Agent) is represented as a dimension so the
// hash covers the whole surface. selector binds the entry to an agent.
type AgentGovernanceV2 struct {
	Selector        SelectorV2           `json:"selector"`
	ACLs            DimACLsV2            `json:"acls"`
	AllowedTools    DimStringSetV2       `json:"allowed_tools"`
	ToolPolicies    DimToolPoliciesV2    `json:"tool_policies"`
	ToolConstraints DimToolConstraintsV2 `json:"tool_constraints"`
	ToolChainRules  DimToolChainRulesV2  `json:"tool_chain_rules"`
	BlockedContent  DimStringSetV2       `json:"blocked_content"`
	ScanProfile     DimScalarStringV2    `json:"scan_profile"`
	Suspended       DimScalarBoolV2      `json:"suspended"`
	Egress          DimAgentEgressV2     `json:"egress"`
}

// DimAgentEgressV2 is the PER-AGENT egress dimension, mirroring
// config.Agent.Egress (config.EgressPolicy) so 9A.2 can project it onto a
// single agent's outbound controls. This is distinct from the body-level
// DimEgressV2, which carries only the fleet/global forward-proxy domain lists.
// The same unmanaged|replace|clear mode discipline used by every other
// dimension applies; apply semantics are 9A.2.
//
// Wire-safety notes:
//   - rate_limit and rate_window are integer counts (config int), carried as
//     int64 so JSON encoding is deterministic. No float fields exist on
//     config.EgressPolicy, so no decimal-string convention is needed here.
//   - config.EgressPolicy.ScanRequests/ScanResponses are *bool (tri-state:
//     unset, true, false). They are carried as a closed-set STRING enum
//     ("unset"|"true"|"false") rather than a JSON null/bool, so the canonical
//     bytes never contain null (which the container discipline forbids) and the
//     tri-state is preserved without a pointer in the signed body.
//   - tool_restrictions mirrors config map[string][]string; map keys serialize
//     alphabetically, so the canonical bytes are deterministic.
//
// Omitted from config.EgressPolicy: nothing operator-relevant is dropped. Every
// EgressPolicy field is represented.
type DimAgentEgressV2 struct {
	Mode              string              `json:"mode"`
	AllowedDomains    []string            `json:"allowed_domains"`
	BlockedDomains    []string            `json:"blocked_domains"`
	Scope             string              `json:"scope"`
	ToolRestrictions  map[string][]string `json:"tool_restrictions"`
	ScanRequests      string              `json:"scan_requests"`  // tri-state: "unset" | "true" | "false"
	ScanResponses     string              `json:"scan_responses"` // tri-state: "unset" | "true" | "false"
	BlockedCategories []string            `json:"blocked_categories"`
	RateLimit         int64               `json:"rate_limit"`
	RateWindow        int64               `json:"rate_window"`
	Integrations      []string            `json:"integrations"`
}

// SelectorV2 selects the agent a governance entry applies to. name is the
// primary key; labels is an optional label match (map keys serialize
// alphabetically, so the canonical bytes are deterministic).
type SelectorV2 struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// DimACLsV2 mirrors the agent ACL surface (config.Agent.CanMessage /
// BlockedContent split into recipient allow/deny here).
type DimACLsV2 struct {
	Mode              string   `json:"mode"`
	AllowedRecipients []string `json:"allowed_recipients"`
	BlockedRecipients []string `json:"blocked_recipients"`
}

// DimStringSetV2 is a string-list dimension (allowed_tools, blocked_content).
type DimStringSetV2 struct {
	Mode   string   `json:"mode"`
	Values []string `json:"values"`
}

// DimToolPoliciesV2 maps a tool name to its policy (config.Agent.ToolPolicies).
// Map keys serialize alphabetically, so the canonical bytes are deterministic.
type DimToolPoliciesV2 struct {
	Mode   string                  `json:"mode"`
	ByTool map[string]ToolPolicyV2 `json:"by_tool"`
}

// ToolPolicyV2 mirrors config.ToolPolicy. Monetary/limit values that are
// float64 in config are carried as STRINGS on the v2 wire (see canonical_v2.go
// for the rationale): a base-10 decimal string has one exact representation, so
// the hash is stable, whereas float JSON formatting is not portably
// deterministic. rate_limit is an integer count and stays an int (integer JSON
// encoding is deterministic). Decimal-string validation happens at verify time;
// numeric interpretation is deferred to 9A.2 apply.
type ToolPolicyV2 struct {
	MaxAmount            string `json:"max_amount"`             // decimal string, e.g. "100.00"
	DailyLimit           string `json:"daily_limit"`            // decimal string
	RequireApprovalAbove string `json:"require_approval_above"` // decimal string
	RateLimit            int64  `json:"rate_limit"`             // integer calls per hour
}

// DimToolConstraintsV2 mirrors config.Agent.ToolConstraints. The list order is
// canonical (hashed as authored).
type DimToolConstraintsV2 struct {
	Mode  string             `json:"mode"`
	Items []ToolConstraintV2 `json:"items"`
}

// ToolConstraintV2 mirrors config.ToolConstraintConfig field-for-field so 9A.2
// maps it 1:1: tool name, the per-parameter constraint map, the max response
// size, and the cooldown. parameters map keys serialize alphabetically, so the
// canonical bytes are deterministic. max_response_bytes and cooldown_secs are
// integer counts (config int), carried as int64 for deterministic JSON.
type ToolConstraintV2 struct {
	Tool             string                       `json:"tool"`
	Parameters       map[string]ParamConstraintV2 `json:"parameters"`
	MaxResponseBytes int64                        `json:"max_response_bytes"`
	CooldownSecs     int64                        `json:"cooldown_secs"`
}

// ParamConstraintV2 mirrors config.ParamConstraintConfig field-for-field:
// allowed/blocked glob patterns and a max length. max_length is an integer
// count carried as int64 for deterministic JSON.
type ParamConstraintV2 struct {
	AllowedPatterns []string `json:"allowed_patterns"`
	BlockedPatterns []string `json:"blocked_patterns"`
	MaxLength       int64    `json:"max_length"`
}

// DimToolChainRulesV2 mirrors config.Agent.ToolChainRules. List order is
// canonical.
type DimToolChainRulesV2 struct {
	Mode  string            `json:"mode"`
	Items []ToolChainRuleV2 `json:"items"`
}

// ToolChainRuleV2 mirrors config.ToolChainRuleConfig field-for-field so 9A.2
// maps it 1:1: the triggering tool (if), the tools that become blocked (then),
// and how long the block lasts (cooldown_secs). cooldown_secs is an integer
// count (config int) carried as int64 for deterministic JSON.
type ToolChainRuleV2 struct {
	If           string   `json:"if"`
	Then         []string `json:"then"`
	CooldownSecs int64    `json:"cooldown_secs"`
}

// DimScalarStringV2 is a single-string dimension (scan_profile).
type DimScalarStringV2 struct {
	Mode  string `json:"mode"`
	Value string `json:"value"`
}

// DimScalarBoolV2 is a single-bool dimension (suspended).
type DimScalarBoolV2 struct {
	Mode  string `json:"mode"`
	Value bool   `json:"value"`
}
