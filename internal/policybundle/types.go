// Package policybundle verifies a signed policy_bundle.v1 artifact
// strongly enough to apply it to the local Oktsec runtime config.
//
// This is stricter than the snapshot-time verification a node does when
// it reports an active policy. Reporting verification authenticates the
// signature over the bundle's declared policy hash. Apply verification
// additionally recomputes the policy hash from the bundle body and
// requires the signing key's fingerprint to match an operator-supplied
// trust fingerprint, so a bundle is never trusted for apply merely
// because it is present on disk.
//
// The package owns the policy_bundle.v1 wire contract on the Community
// side: the typed body layout, the canonicalization, and the
// domain-separated signing payload. A vendored signed fixture guards
// these bytes against drift — if any of them diverge from the contract
// the fixture's signature stops verifying, which is the right failure
// mode. It imports nothing outside the standard library.
package policybundle

// Frozen constants of the policy_bundle.v1 signing contract. A change to
// any of these is a contract change: it must be matched on the signing
// side, and the vendored fixture must be regenerated. Drift here surfaces
// as a broken signature on every bundle.
const (
	SchemaVersion    = "policy_bundle.v1"
	BundleVersion    = 1
	Canonicalization = "oktsec-policy-v1-typed-utc-json"
	SignatureAlg     = "Ed25519"
)

// PolicyBundle is the signed JSON artifact: the outer envelope carries
// the declared hash and the signature; the inner PolicyBody is the
// signed content.
type PolicyBundle struct {
	SchemaVersion    string          `json:"schema_version"`
	BundleVersion    int             `json:"bundle_version"`
	PolicyHash       string          `json:"policy_hash"`
	Canonicalization string          `json:"canonicalization"`
	Policy           PolicyBody      `json:"policy"`
	Signature        PolicySignature `json:"signature"`
}

// PolicyBody is the content covered by policy_hash and the Ed25519
// signature. The field order IS the canonical projection order: the
// signed bytes are produced by encoding this struct exactly as declared.
// Never reorder these fields or change a json tag without changing
// Canonicalization and regenerating the fixture.
type PolicyBody struct {
	PolicyID      string          `json:"policy_id"`
	PolicyVersion string          `json:"policy_version"`
	Mode          string          `json:"mode"`
	Rules         PolicyRules     `json:"rules"`
	Gateway       PolicyGateway   `json:"gateway"`
	Egress        PolicyEgress    `json:"egress"`
	Redaction     PolicyRedaction `json:"redaction"`
	Metadata      PolicyMetadata  `json:"metadata"`
}

// PolicyRules is the rule-ID layer. Overrides keys map a rule id to its
// action; map keys serialize alphabetically under encoding/json, so the
// canonical bytes are deterministic without explicit sorting.
type PolicyRules struct {
	Enabled   []string                      `json:"enabled"`
	Disabled  []string                      `json:"disabled"`
	Overrides map[string]PolicyRuleOverride `json:"overrides"`
}

type PolicyRuleOverride struct {
	Action string `json:"action"`
}

type PolicyGateway struct {
	ToolsAllowed []string `json:"tools_allowed"`
	ToolsDenied  []string `json:"tools_denied"`
}

type PolicyEgress struct {
	DomainsAllowed []string `json:"domains_allowed"`
	DomainsDenied  []string `json:"domains_denied"`
}

type PolicyRedaction struct {
	Level string `json:"level"`
}

type PolicyMetadata struct {
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
	Reason    string `json:"reason"`
}

// PolicySignature carries the Ed25519 signature and the key material the
// signing payload binds. key_id and public_key_fingerprint are covered by
// the signature, so they cannot be rewritten post-sign without breaking it.
type PolicySignature struct {
	Alg                  string `json:"alg"`
	KeyID                string `json:"key_id"`
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	SignedAt             string `json:"signed_at"`
	Value                string `json:"value"`
}
