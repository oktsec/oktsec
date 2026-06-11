// Package node implements the local node identity and read-only
// snapshot contract for Phase 5 Order 1. Community owns the local
// runtime node; downstream verifiers consume the JSON artifacts this
// package emits without importing internal/ Go code.
//
// Everything in this package must remain additive and read-only.
// Snapshot must not create databases, run migrations, install hooks,
// touch external client config, or modify oktsec.yaml. Node identity
// lives under config.HomeDir()/node/ so it stays separate from agent
// keys and from the YAML config.
package node

// Warning is a structured non-fatal diagnostic emitted by the snapshot
// builder when partial state is observed. The Code is a stable
// snake_case identifier consumers can branch on; Message is a short
// human-readable description.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Stable warning codes. New codes may be appended; existing codes must
// not change spelling, because downstream consumers and Order 2 evidence
// checkpoints branch on them.
const (
	WarnNodeIdentityMissing            = "node_identity_missing"
	WarnNodeIdentityInvalid            = "node_identity_invalid"
	WarnConfigMissing                  = "config_missing"
	WarnConfigInvalid                  = "config_invalid"
	WarnDBMissing                      = "db_missing"
	WarnDBUnreachable                  = "db_unreachable"
	WarnAuditTableMissing              = "audit_table_missing"
	WarnRuntimeTableMissing            = "runtime_table_missing"
	WarnActivityTableMissing           = "activity_table_missing"
	WarnAuditChainUnavailable          = "audit_chain_unavailable"
	WarnAuditChainSignaturesNotChecked = "audit_chain_signatures_not_checked"
	WarnAuditChainSignaturesPartial    = "audit_chain_signatures_partial"
	WarnClientDiscoveryNotIncluded     = "client_discovery_not_included"
	WarnPostgresSnapshotLimited        = "postgres_snapshot_limited"
	WarnPolicyBundleUnreadable         = "policy_bundle_unreadable"
)
