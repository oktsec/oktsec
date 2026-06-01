package node

// Stable schema versions emitted in JSON output. Bumping a version is a
// breaking-change signal to Enterprise consumers and must be done in a
// dedicated PR with a migration note.
const (
	SchemaIdentity = "node_identity.v1"
	SchemaSnapshot = "node_snapshot.v1"
)

// Install profile values for node identity. Display/planning only;
// nothing in the policy hot path branches on this field.
const (
	ProfileLocal      = "local"
	ProfileEnterprise = "enterprise"
)

// Identity is the on-disk and JSON-emitted shape of the local node
// identity record. NodeID is non-secret, stable, and randomly
// generated; host/public-key fingerprints are SHA-256 hashes that
// must never expose raw hostname or username material.
type Identity struct {
	SchemaVersion        string            `json:"schema_version"`
	NodeID               string            `json:"node_id"`
	CreatedAt            string            `json:"created_at"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
	HostFingerprint      string            `json:"host_fingerprint"`
	InstallProfile       string            `json:"install_profile"`
	Labels               map[string]string `json:"labels,omitempty"`
}

// IdentityStatus is the JSON envelope returned by `oktsec node status`.
// Status is one of "present", "missing", "invalid"; Identity is set
// only when Status is "present". Warnings are non-fatal.
type IdentityStatus struct {
	Status   string    `json:"status"`
	Identity *Identity `json:"identity,omitempty"`
	Warnings []Warning `json:"warnings,omitempty"`
}

// Snapshot is the top-level JSON shape emitted by
// `oktsec node snapshot --json`. Sections are populated on a best-effort
// basis; partial state is reported via Warnings instead of failing.
type Snapshot struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Range         SnapshotRange    `json:"range"`
	Node          SnapshotNode     `json:"node"`
	Config        SnapshotConfig   `json:"config"`
	Surfaces      SnapshotSurfaces `json:"surfaces"`
	Inventory     SnapshotInventory `json:"inventory"`
	Posture       SnapshotPosture  `json:"posture"`
	Evidence      SnapshotEvidence `json:"evidence"`
	Policy        *SnapshotPolicy  `json:"policy,omitempty"`
	Warnings      []Warning        `json:"warnings"`
}

// Policy status values reported in SnapshotPolicy.PolicyStatus.
const (
	// PolicyStatusActive: a local policy bundle was found and its
	// declared policy_hash was read. NOT a verification claim.
	PolicyStatusActive = "active"
	// PolicyStatusNone: no --policy-bundle path was supplied; the node
	// has no locally-declared active policy.
	PolicyStatusNone = "none"
	// PolicyStatusUnreadable: a path was supplied but the bundle could
	// not be read or parsed, or it lacked the minimal fields. Distinct
	// from PolicyStatusNone so Enterprise does not mistake "I could not
	// read it" for "there is no policy here".
	PolicyStatusUnreadable = "unreadable"
)

// Policy source values reported in SnapshotPolicy.ActivePolicySource.
const (
	// PolicySourceLocalFile: a local bundle path was supplied (active
	// or unreadable — source records where the node looked).
	PolicySourceLocalFile = "local_file"
	// PolicySourceNone: no bundle path was supplied.
	PolicySourceNone = "none"
)

// Policy verification status values (Order 4C.1) reported in
// SnapshotPolicy.ActivePolicyVerificationStatus. "verified" means
// exactly that the Ed25519 signature over the declared policy hash
// verified against a trusted key — NOT that the policy body was
// re-validated or applied.
const (
	// PolicyVerificationVerified: signature verified against the
	// configured trust fingerprint.
	PolicyVerificationVerified = "verified"
	// PolicyVerificationNoTrustAnchor: a bundle is present but no
	// --policy-trust-fingerprint was configured, so the node cannot
	// claim the signing key is trusted.
	PolicyVerificationNoTrustAnchor = "no_trust_anchor"
	// PolicyVerificationSigningKeyMismatch: the bundle's signing key
	// fingerprint does not match the configured trust fingerprint.
	PolicyVerificationSigningKeyMismatch = "signing_key_mismatch"
	// PolicyVerificationSignatureInvalid: the Ed25519 signature did
	// not verify over the reconstructed signing payload.
	PolicyVerificationSignatureInvalid = "signature_invalid"
	// PolicyVerificationBundleUnreadable: the bundle could not be read
	// or parsed (mirrors PolicyStatusUnreadable).
	PolicyVerificationBundleUnreadable = "bundle_unreadable"
	// PolicyVerificationUnsupportedBundle: the bundle parsed but
	// carries no usable signature block / unknown bundle shape, so it
	// cannot be verified.
	PolicyVerificationUnsupportedBundle = "unsupported_bundle"
)

// SnapshotPolicy is the additive Order 4B block reporting which policy
// the node has locally. It is DECLARATIVE evidence only: the node
// echoes the policy_hash the bundle declares and does not verify the
// signature, recompute the hash, or apply the policy. Signature
// verification and application are deferred to Order 4C.
//
// The block is carried as a pointer on Snapshot with omitempty so a
// pre-4B snapshot (no policy key) reproduces byte-identical canonical
// bytes and existing signed envelopes keep verifying. A 4B+ node always
// populates it, including the PolicyStatusNone case.
type SnapshotPolicy struct {
	// ActivePolicyHash is the policy_hash echoed from the local
	// bundle. Empty when PolicyStatus is none or unreadable. NOT
	// recomputed by the node and NOT a verification result.
	ActivePolicyHash string `json:"active_policy_hash"`
	// ActivePolicyID / ActivePolicyVersion mirror the bundle's
	// declared identity. Omitted when not active.
	ActivePolicyID      string `json:"active_policy_id,omitempty"`
	ActivePolicyVersion string `json:"active_policy_version,omitempty"`
	// ActivePolicySource is local_file when a path was supplied,
	// none otherwise.
	ActivePolicySource string `json:"active_policy_source"`
	// ActivePolicyLoadedAt is the local bundle file's modification
	// time (UTC RFC3339) — when the bundle landed on the node, a
	// staleness signal. Omitted when not active.
	ActivePolicyLoadedAt string `json:"active_policy_loaded_at,omitempty"`
	// ActivePolicyVerified is the Order 4C.1 verification result: true
	// only when the bundle's signature over the declared policy hash
	// verified against the operator-configured trust fingerprint. It
	// does NOT assert the policy body was re-validated or applied.
	ActivePolicyVerified bool `json:"active_policy_verified"`
	// ActivePolicyVerificationStatus (Order 4C.1) reports which check
	// decided ActivePolicyVerified: verified / no_trust_anchor /
	// signing_key_mismatch / signature_invalid / bundle_unreadable /
	// unsupported_bundle. Omitted when no bundle path was supplied.
	ActivePolicyVerificationStatus string `json:"active_policy_verification_status,omitempty"`
	// PolicyStatus is one of active / none / unreadable.
	PolicyStatus string `json:"policy_status"`
}

// SnapshotRange describes the time window the snapshot was computed
// over. Both bounds are RFC3339 strings; Until empty means "now".
type SnapshotRange struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// SnapshotNode summarizes the local Oktsec runtime that produced this
// snapshot. IdentityStatus mirrors IdentityStatus.Status above so the
// section is self-describing when identity is missing.
type SnapshotNode struct {
	NodeID               string `json:"node_id,omitempty"`
	IdentityStatus       string `json:"identity_status"`
	HostFingerprint      string `json:"host_fingerprint,omitempty"`
	PublicKeyFingerprint string `json:"public_key_fingerprint,omitempty"`
	OktsecVersion        string `json:"oktsec_version,omitempty"`
	Commit               string `json:"commit,omitempty"`
	GOOS                 string `json:"goos"`
	GOARCH               string `json:"goarch"`
	Profile              string `json:"profile,omitempty"`
}

// SnapshotConfig reports the state of oktsec.yaml without exposing
// secrets or full paths. ConfigHash is SHA-256 of the raw file bytes;
// PathHash is SHA-256 of the absolute path.
type SnapshotConfig struct {
	Status              string `json:"status"`
	PathTail            string `json:"path_tail,omitempty"`
	PathHash            string `json:"path_hash,omitempty"`
	ConfigHash          string `json:"config_hash,omitempty"`
	DefaultPolicy       string `json:"default_policy,omitempty"`
	SignatureRequired   bool   `json:"signature_required"`
	DelegationRequired  bool   `json:"delegation_required"`
	DBBackend           string `json:"db_backend,omitempty"`
	DBAvailable         bool   `json:"db_available"`
}

// SnapshotSurfaces is the per-surface configured/observed view used by
// the dashboard coverage matrix and by the planned Enterprise fleet
// report. Booleans are conservative: false when the section cannot
// prove the affirmative.
type SnapshotSurfaces struct {
	MCPGateway      SurfaceGateway  `json:"mcp_gateway"`
	StdioProxy      SurfaceStdio    `json:"stdio_proxy"`
	Hooks           SurfaceHooks    `json:"hooks"`
	EgressProxy     SurfaceEgress   `json:"egress_proxy"`
	AgentMessageAPI SurfaceAgentMsg `json:"agent_message_api"`
}

// SurfaceGateway summarizes the MCP gateway surface.
type SurfaceGateway struct {
	Configured     bool `json:"configured"`
	Enabled        bool `json:"enabled"`
	AuthRequired   bool `json:"auth_required"`
	BackendCount   int  `json:"backend_count"`
	ScanResponses  bool `json:"scan_responses"`
}

// SurfaceStdio summarizes the stdio proxy surface. Source is
// "config_only" in Order 1; future orders may add "discovered".
type SurfaceStdio struct {
	Configured         bool   `json:"configured"`
	WrappedClientCount int    `json:"wrapped_client_count"`
	Source             string `json:"source"`
}

// SurfaceHooks summarizes the hook ingestion surface.
type SurfaceHooks struct {
	Configured      bool `json:"configured"`
	AuthRequired    bool `json:"auth_required"`
	FreshRealEvent  bool `json:"fresh_real_event"`
	HeartbeatRecent bool `json:"heartbeat_recent"`
}

// SurfaceEgress summarizes the HTTP egress proxy surface.
type SurfaceEgress struct {
	Configured          bool `json:"configured"`
	Enabled             bool `json:"enabled"`
	AuthRequired        bool `json:"auth_required"`
	AllowedDomainCount  int  `json:"allowed_domain_count"`
	BlockedDomainCount  int  `json:"blocked_domain_count"`
}

// SurfaceAgentMsg summarizes the inter-agent message API surface.
type SurfaceAgentMsg struct {
	Configured         bool `json:"configured"`
	SignatureRequired  bool `json:"signature_required"`
	DelegationRequired bool `json:"delegation_required"`
}

// SnapshotInventory enumerates what this node is configured to protect.
// Arrays are sorted by stable id so diff tooling is stable across runs.
type SnapshotInventory struct {
	Agents     []InventoryAgent     `json:"agents"`
	Principals []InventoryPrincipal `json:"principals"`
	MCPServers []InventoryMCPServer `json:"mcp_servers"`
	Tools      []InventoryTool      `json:"tools"`
	Clients    []InventoryClient    `json:"clients"`
}

// InventoryAgent is a redacted projection of config.Agent.
type InventoryAgent struct {
	ID        string   `json:"id"`
	Suspended bool     `json:"suspended"`
	Tags      []string `json:"tags,omitempty"`
}

// InventoryPrincipal is a redacted projection of config.PrincipalConfig.
type InventoryPrincipal struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind,omitempty"`
	WorkspaceIDHash string   `json:"workspace_id_hash,omitempty"`
	Surfaces        []string `json:"surfaces,omitempty"`
}

// InventoryMCPServer is a redacted projection of config.MCPServerConfig.
// Command paths and URLs are reduced to tail + host so secrets in args
// or query strings never appear in the snapshot.
type InventoryMCPServer struct {
	Name        string `json:"name"`
	Transport   string `json:"transport"`
	CommandTail string `json:"command_tail,omitempty"`
	ArgsCount   int    `json:"args_count"`
	URLHostHash string `json:"url_host_hash,omitempty"`
	EnvCount    int    `json:"env_count"`
}

// InventoryTool is a tool the node knows about. Source is one of
// "runtime" (observed via runtime_hook_events) or "config"; in Order 1
// the inventory comes primarily from runtime when available.
type InventoryTool struct {
	Name            string `json:"name"`
	Source          string `json:"source"`
	Server          string `json:"server,omitempty"`
	SchemaHash      string `json:"schema_hash,omitempty"`
	DescriptionHash string `json:"description_hash,omitempty"`
}

// InventoryClient is a discovered AI client (Claude Desktop, Cursor,
// etc.). Order 1 emits an empty array with a `client_discovery_not_included`
// warning; later orders populate this when --include-discovery is set.
type InventoryClient struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// SnapshotPosture summarizes the node's protection coverage using the
// same vocabulary as the dashboard coverage matrix. Overall is one of
// protected/observing/blind/setup_pending/degraded.
type SnapshotPosture struct {
	Overall            string         `json:"overall"`
	SurfaceCounts      PostureCounts  `json:"surface_counts"`
	RuntimeSessions    int            `json:"runtime_sessions"`
	ActivePrincipals   int            `json:"active_principals"`
	BlockedActions     int            `json:"blocked_actions"`
	QuarantinedActions int            `json:"quarantined_actions"`
}

// PostureCounts breaks down configured surfaces by coverage state.
type PostureCounts struct {
	Protected     int `json:"protected"`
	Observed      int `json:"observed"`
	Blind         int `json:"blind"`
	Stale         int `json:"stale"`
	NotConfigured int `json:"not_configured"`
}

// SnapshotEvidence reports aggregate counts and chain-verification
// results from the audit/runtime/activity tables. Counts respect the
// snapshot range; chain verification is bounded by a fixed limit and
// the entry-count scope is reported in AuditChainVerificationScope.
//
// AuditChainVerified is the overall result under the checks the
// snapshot was able to run. It is false if hash links break OR if
// any signature that *was* checked against the configured proxy key
// failed. It is true only when every applicable check passed.
//
// AuditChainSignaturesChecked is the stronger signature claim:
// true only when every entry in the verified scope carried a
// proxy_signature AND every one of those signatures verified
// against the configured proxy public key. Anything weaker —
// no key reachable, no signed rows, or mixed signed/unsigned
// coverage — leaves this field false. Enterprise compliance
// evidence must read both fields together: AuditChainVerified
// tells you nothing tampered; AuditChainSignaturesChecked tells
// you the proxy actually signed every row in scope.
type SnapshotEvidence struct {
	AuditAvailable               bool             `json:"audit_available"`
	AuditEntries                 int              `json:"audit_entries"`
	AuditChainHead               string           `json:"audit_chain_head,omitempty"`
	AuditChainVerified           bool             `json:"audit_chain_verified"`
	AuditChainVerificationScope  string           `json:"audit_chain_verification_scope,omitempty"`
	AuditChainSignaturesChecked  bool             `json:"audit_chain_signatures_checked"`
	AuditChainKeyFingerprint     string           `json:"audit_chain_key_fingerprint,omitempty"`
	AuditOldestAt                string           `json:"audit_oldest_at,omitempty"`
	AuditNewestAt                string           `json:"audit_newest_at,omitempty"`
	RuntimeAvailable             bool             `json:"runtime_available"`
	RuntimeSessions              int              `json:"runtime_sessions"`
	RuntimeEvents                int              `json:"runtime_events"`
	RuntimeToolEvents            int              `json:"runtime_tool_events"`
	ActivityAvailable            bool             `json:"activity_available"`
	ActivityEvents               int              `json:"activity_events"`
	Decisions                    DecisionCounts   `json:"decisions"`
}

// DecisionCounts breaks audit entries down by policy_decision /
// status. Reported as plain integers so dashboards and dashboards-of-
// dashboards can diff snapshots field-by-field.
type DecisionCounts struct {
	Allowed     int `json:"allowed"`
	Flagged     int `json:"flagged"`
	Quarantined int `json:"quarantined"`
	Blocked     int `json:"blocked"`
	Rejected    int `json:"rejected"`
}
