package policybundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// VerifiedBundleV2 is the typed result of a successful VerifyBundleV2. The
// caller gets the decoded bundle, the recomputed canonical body bytes, the
// recomputed policy hash, and the matched key fingerprint. issued_at is
// already validated canonical, so it is exposed verbatim as the authoritative
// time of the assignment.
type VerifiedBundleV2 struct {
	Bundle           *PolicyBundleV2
	CanonicalBody    []byte
	PolicyHash       string
	TrustFingerprint string
	IssuedAtUTC      string
}

// VerifyBundleV2 decodes and verifies a signed policy_bundle.v2 strongly
// enough to apply it. It mirrors VerifyBundle's fixed check order over the v2
// body, reusing the v1 RejectCode set. No apply/projection happens here - that
// is 9A.2. The checks fire cheapest-first:
//
//  1. strict JSON decode + EOF (rejects unknown fields and trailing tokens)
//     and duplicate-object-key rejection
//  2. schema_version / bundle_version / canonicalization / signature.alg
//     (all the v2 constants)
//  3. canonical-form + schema checks (all policy_schema_invalid): timestamps
//     (created_at, issued_at, signed_at) canonical; ALL containers present as []/{};
//     required scalar fields non-empty; signed-model enums in range (bundle
//     mode, every dimension mode incl. rejecting "merge", redaction.level,
//     override actions, target.scope); sequence >= 1; decimal strings canonical
//  4. body re-canonicalization + policy hash recompute over exact wire strings
//  5. signature public key shape (base64 + Ed25519 length)
//  6. signature self-consistency (sha256(public_key) == claimed fingerprint)
//  7. trust fingerprint match (the operator's apply trust decision)
//  8. Ed25519 verify over the v2 signing payload, binding assignment, target,
//     sequence, issued_at, and rollback_of
func VerifyBundleV2(raw []byte, trustFingerprint string) (*VerifiedBundleV2, error) {
	if trustFingerprint == "" {
		return nil, ErrTrustFingerprintRequired
	}

	// (1) strict decode + EOF.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b PolicyBundleV2
	if err := dec.Decode(&b); err != nil {
		return nil, reject(RejectDecode, "decode: %s", err)
	}
	var trailing json.RawMessage
	switch err := dec.Decode(&trailing); {
	case errors.Is(err, io.EOF):
		// clean termination - the only acceptable path
	case err == nil:
		return nil, reject(RejectDecode, "trailing JSON content after the bundle")
	default:
		return nil, reject(RejectDecode, "trailing content after the bundle: %s", err)
	}

	// Duplicate object keys: encoding/json keeps the last value silently, so a
	// signed bundle could show one value to a reader and another to the
	// verifier. Reject before trusting any field. Reuses the v1 scanner.
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, reject(RejectSchemaInvalid, "%s", err)
	}

	// (2) schema constant tags.
	switch {
	case b.SchemaVersion != SchemaVersionV2:
		return nil, reject(RejectSchemaInvalid, "schema_version=%q, want %q", b.SchemaVersion, SchemaVersionV2)
	case b.BundleVersion != BundleVersionV2:
		return nil, reject(RejectSchemaInvalid, "bundle_version=%d, want %d", b.BundleVersion, BundleVersionV2)
	case b.Canonicalization != CanonicalizationV2:
		return nil, reject(RejectSchemaInvalid, "canonicalization=%q, want %q", b.Canonicalization, CanonicalizationV2)
	case b.Signature.Alg != SignatureAlg:
		return nil, reject(RejectSchemaInvalid, "signature.alg=%q, want %q", b.Signature.Alg, SignatureAlg)
	}

	// (3) canonical-form checks. created_at and issued_at are both required and
	// must be in the single canonical wire form (a byte-different but parseable
	// timestamp is rejected here, before the hash). signed_at is validated for
	// canonical form too: unlike v1 it is NOT bound by the v2 signature (v2 binds
	// issued_at instead), so a malformed or mutable signed_at would otherwise ride
	// through to a "verified" bundle. Catching it here as a schema reject keeps
	// every timestamp the verifier exposes canonical. Containers must be []/{}.
	// Enums and sequence are range-checked. Decimal strings must be canonical.
	if err := validateCanonicalPolicyTimestamp(b.Policy.Metadata.CreatedAt); err != nil {
		return nil, reject(RejectSchemaInvalid, "policy.metadata.created_at %s", err)
	}
	if err := validateCanonicalPolicyTimestamp(b.Policy.Assignment.IssuedAt); err != nil {
		return nil, reject(RejectSchemaInvalid, "policy.assignment.issued_at %s", err)
	}
	if err := validateCanonicalPolicyTimestamp(b.Signature.SignedAt); err != nil {
		return nil, reject(RejectSchemaInvalid, "signature.signed_at %s", err)
	}
	if err := validateCanonicalPolicyContainersV2(b.Policy); err != nil {
		return nil, reject(RejectSchemaInvalid, "%s", err)
	}
	if err := validatePolicySchemaV2(&b); err != nil {
		return nil, reject(RejectSchemaInvalid, "%s", err)
	}

	// (4) re-canonicalize and recompute the hash from EXACT wire strings.
	computed, canonical, err := policyHashHexV2(b.Policy)
	if err != nil {
		return nil, reject(RejectSchemaInvalid, "canonicalize body: %s", err)
	}
	if computed != b.PolicyHash {
		return nil, reject(RejectHashMismatch, "claimed=%s computed=%s", b.PolicyHash, computed)
	}

	// (5) public key shape.
	pub, err := base64.StdEncoding.DecodeString(b.Signature.PublicKey)
	if err != nil {
		return nil, reject(RejectUnsupportedBundle, "signature.public_key base64 decode: %s", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, reject(RejectUnsupportedBundle, "signature.public_key length=%d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// (6) self-consistency: the embedded key must hash to the claimed fingerprint.
	derivedFP := publicKeyFingerprint(ed25519.PublicKey(pub))
	if derivedFP != b.Signature.PublicKeyFingerprint {
		return nil, reject(RejectUnsupportedBundle,
			"signature.public_key_fingerprint claimed=%s computed=%s", b.Signature.PublicKeyFingerprint, derivedFP)
	}

	// (7) trust fingerprint match - the operator's apply trust decision.
	if derivedFP != trustFingerprint {
		return nil, reject(RejectSigningKeyMismatch,
			"bundle signing key %s does not match trust fingerprint %s", derivedFP, trustFingerprint)
	}

	// (8) signature value + Ed25519 verify over the v2 canonical payload. The
	// payload binds the assignment, target, sequence, issued_at, and
	// rollback_of as exact wire bytes (issued_at already validated canonical in
	// step 3), so any edit to those breaks the signature.
	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, reject(RejectSignatureInvalid, "signature.value is not a valid Ed25519 signature")
	}
	payload := policyBundleV2SigningPayload(
		b.Policy.PolicyID, b.Policy.PolicyVersion, b.PolicyHash,
		b.Policy.Assignment.AssignmentID, b.Policy.Assignment.Target.Scope,
		b.Policy.Assignment.Target.NodeID, b.Policy.Assignment.IssuedAt,
		b.Policy.Assignment.Sequence, b.Policy.Assignment.RollbackOf,
		b.Signature.KeyID, b.Signature.PublicKeyFingerprint)
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sigBytes) {
		return nil, reject(RejectSignatureInvalid, "signature does not verify over the policy_bundle.v2 signing payload")
	}

	return &VerifiedBundleV2{
		Bundle:           &b,
		CanonicalBody:    canonical,
		PolicyHash:       computed,
		TrustFingerprint: derivedFP,
		IssuedAtUTC:      b.Policy.Assignment.IssuedAt,
	}, nil
}

// validatePolicySchemaV2 enforces required-non-empty scalar fields, the
// signed-model enum value sets (including every dimension mode and rejecting
// "merge"), sequence range, and decimal-string form. Returns an error (mapped
// to policy_schema_invalid by the caller) on the first violation. Fields
// covered by other checks are not re-validated here: schema/canonicalization/
// alg tags, policy_hash, created_at/issued_at, public_key/fingerprint/value,
// and container presence.
func validatePolicySchemaV2(b *PolicyBundleV2) error {
	// TODO(9A.2): reject self-referential rollback_of (rollback_of ==
	// assignment_id) at apply validation; it has no verify-time effect here.
	for _, f := range []struct{ name, val string }{
		{"policy.policy_id", b.Policy.PolicyID},
		{"policy.policy_version", b.Policy.PolicyVersion},
		{"policy.assignment.assignment_id", b.Policy.Assignment.AssignmentID},
		{"policy.metadata.created_by", b.Policy.Metadata.CreatedBy},
		{"policy.metadata.reason", b.Policy.Metadata.Reason},
		{"signature.key_id", b.Signature.KeyID},
	} {
		if f.val == "" {
			return fmt.Errorf("%s must not be empty", f.name)
		}
	}

	// Bundle-wide mode (reuses the v1 enforce/observe set).
	if !validModes[b.Policy.Mode] {
		return fmt.Errorf("policy.mode %q not in {enforce, observe}", b.Policy.Mode)
	}

	// Assignment binding. scope is closed-set; node_id is bound to scope so a
	// node assignment names its node and a fleet assignment carries none. A
	// stray node_id on a fleet bundle is still signed, so it is not a forgery,
	// but it lets two byte-different signed artifacts mean the same thing and
	// muddies the target contract 9A.2 apply builds on, so it is rejected.
	scope := b.Policy.Assignment.Target.Scope
	nodeID := b.Policy.Assignment.Target.NodeID
	if !validTargetScope[scope] {
		return fmt.Errorf("policy.assignment.target.scope %q not in {fleet, node}", scope)
	}
	switch scope {
	case "node":
		if nodeID == "" {
			return fmt.Errorf("policy.assignment.target.node_id must not be empty when scope is node")
		}
	case "fleet":
		if nodeID != "" {
			return fmt.Errorf("policy.assignment.target.node_id must be empty when scope is fleet, got %q", nodeID)
		}
	}
	// TODO(9A.2): normalize/validate target.node_id charset and shape at apply,
	// where it is compared to the local node id.
	if b.Policy.Assignment.Sequence < 1 {
		return fmt.Errorf("policy.assignment.sequence %d must be >= 1", b.Policy.Assignment.Sequence)
	}

	// Top-level dimension modes.
	for _, d := range []struct{ name, mode string }{
		{"policy.rules.mode", b.Policy.Rules.Mode},
		{"policy.gateway.mode", b.Policy.Gateway.Mode},
		{"policy.egress.mode", b.Policy.Egress.Mode},
		{"policy.redaction.mode", b.Policy.Redaction.Mode},
		{"policy.governance.server.mode", b.Policy.Governance.Server.Mode},
	} {
		if err := checkDimMode(d.name, d.mode); err != nil {
			return err
		}
	}

	// redaction.level reuses the v1 set.
	if !validRedactionLevels[b.Policy.Redaction.Level] {
		return fmt.Errorf("policy.redaction.level %q not in {full, analyst, external}", b.Policy.Redaction.Level)
	}

	// Rule overrides reuse the v1 action set.
	for id, ov := range b.Policy.Rules.Overrides {
		if !validOverrideActions[ov.Action] {
			return fmt.Errorf("policy.rules.overrides[%q].action %q not in {flag, quarantine, block}", id, ov.Action)
		}
	}

	// Per-agent governance dimensions.
	for i := range b.Policy.Governance.Agents {
		a := &b.Policy.Governance.Agents[i]
		p := fmt.Sprintf("policy.governance.agents[%d]", i)
		if a.Selector.Name == "" {
			return fmt.Errorf("%s.selector.name must not be empty", p)
		}
		for _, d := range []struct{ name, mode string }{
			{p + ".acls.mode", a.ACLs.Mode},
			{p + ".allowed_tools.mode", a.AllowedTools.Mode},
			{p + ".tool_policies.mode", a.ToolPolicies.Mode},
			{p + ".tool_constraints.mode", a.ToolConstraints.Mode},
			{p + ".tool_chain_rules.mode", a.ToolChainRules.Mode},
			{p + ".blocked_content.mode", a.BlockedContent.Mode},
			{p + ".scan_profile.mode", a.ScanProfile.Mode},
			{p + ".suspended.mode", a.Suspended.Mode},
		} {
			if err := checkDimMode(d.name, d.mode); err != nil {
				return err
			}
		}
		for tool, tp := range a.ToolPolicies.ByTool {
			tpName := fmt.Sprintf("%s.tool_policies.by_tool[%q]", p, tool)
			if err := validateCanonicalDecimal(tpName+".max_amount", tp.MaxAmount); err != nil {
				return err
			}
			if err := validateCanonicalDecimal(tpName+".daily_limit", tp.DailyLimit); err != nil {
				return err
			}
			if err := validateCanonicalDecimal(tpName+".require_approval_above", tp.RequireApprovalAbove); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkDimMode validates a dimension mode against the v2 set. "merge" is
// deliberately out of range in 9A (deferred), so it is rejected here.
func checkDimMode(field, mode string) error {
	if !validDimModes[mode] {
		return fmt.Errorf("%s %q not in {unmanaged, replace, clear}", field, mode)
	}
	return nil
}
