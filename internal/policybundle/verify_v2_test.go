package policybundle

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// fixtureBytesV2 is a deterministically signed policy_bundle.v2 produced by the
// in-package generator (deleted after vendoring), embedded verbatim. It guards
// the v2 canonicalization + signing payload against drift on every CI run: if
// any of them diverge from the contract the fixture's signature stops
// verifying.
//
//go:embed policy_bundle_v2_fixture.json
var fixtureBytesV2 []byte

func loadFixtureV2(t *testing.T) (raw []byte, trustFP string) {
	t.Helper()
	var b PolicyBundleV2
	if err := json.Unmarshal(fixtureBytesV2, &b); err != nil {
		t.Fatalf("decode v2 fixture: %v", err)
	}
	return fixtureBytesV2, b.Signature.PublicKeyFingerprint
}

// remarshalV2 mutates the v2 fixture's typed form and returns valid JSON the
// strict verifier accepts structurally (so a check past decode can fire).
func remarshalV2(t *testing.T, mutate func(b *PolicyBundleV2)) []byte {
	t.Helper()
	raw, _ := loadFixtureV2(t)
	var b PolicyBundleV2
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	mutate(&b)
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// (1) v1 fixture STILL verifies byte-identically (v1 frozen).
func TestV2_V1FixtureStillVerifies(t *testing.T) {
	raw, fp := loadFixture(t)
	v, err := VerifyBundle(raw, fp)
	if err != nil {
		t.Fatalf("v1 fixture must still verify after v2 lands: %v", err)
	}
	if v.Bundle.PolicyHash != v.PolicyHash {
		t.Fatalf("v1 declared %s != recomputed %s", v.Bundle.PolicyHash, v.PolicyHash)
	}
}

// (2) v2 fixture verifies (trust fingerprint = its signing key fp).
func TestV2_FixtureVerifies(t *testing.T) {
	raw, fp := loadFixtureV2(t)
	v, err := VerifyBundleV2(raw, fp)
	if err != nil {
		t.Fatalf("v2 fixture must verify: %v", err)
	}
	if v.Bundle.PolicyHash != v.PolicyHash {
		t.Fatalf("declared %s != recomputed %s", v.Bundle.PolicyHash, v.PolicyHash)
	}
	if len(v.CanonicalBody) == 0 {
		t.Fatal("canonical body must be returned")
	}
	if v.TrustFingerprint != fp {
		t.Fatalf("trust fingerprint = %q, want %q", v.TrustFingerprint, fp)
	}
	if v.IssuedAtUTC != v.Bundle.Policy.Assignment.IssuedAt {
		t.Fatalf("issued_at = %q, want %q", v.IssuedAtUTC, v.Bundle.Policy.Assignment.IssuedAt)
	}
}

// TestV2_HashMatchesContract is the anti-drift guard: the Community v2
// canonicalizer must reproduce, byte-for-byte, the policy hash the signer
// declared.
func TestV2_HashMatchesContract(t *testing.T) {
	raw, _ := loadFixtureV2(t)
	var b PolicyBundleV2
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	computed, _, err := policyHashHexV2(b.Policy)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if computed != b.PolicyHash {
		t.Fatalf("v2 canonicalizer drift: declared=%s computed=%s", b.PolicyHash, computed)
	}
}

// (3) v2 hash changes on any signed-body change.
func TestV2_TamperedBody(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Mode = "observe" })
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

// (4) unknown field -> reject.
func TestV2_UnknownField(t *testing.T) {
	raw, fp := loadFixtureV2(t)
	injected := append([]byte(`{"x_unknown_field": 1,`), raw[1:]...)
	_, err := VerifyBundleV2(injected, fp)
	wantReject(t, err, RejectDecode)
}

// (5) duplicate object key -> reject. A duplicated key defeats the v2 signed
// body's guarantees, since encoding/json silently keeps the last value while a
// JSON reader may take the first; the verifier and a reader could then disagree
// on exactly the anti-rollback/target fields the signature is meant to bind.
// Cover a top-level key, a nested metadata key, and the security-critical
// anti-rollback/target fields (sequence, assignment_id, target.scope).
func TestV2_DuplicateKeysRejected(t *testing.T) {
	raw, fp := loadFixtureV2(t)
	dup := append([]byte(`{"policy_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",`), raw[1:]...)
	_, err := VerifyBundleV2(dup, fp)
	wantReject(t, err, RejectSchemaInvalid)

	nested := bytesReplaceOnce(t, raw, `"created_by"`, `"created_by":"x","created_by"`)
	_, err = VerifyBundleV2(nested, fp)
	wantReject(t, err, RejectSchemaInvalid)

	// Anti-rollback field: a second "sequence" inside the assignment object.
	seqDup := bytesReplaceOnce(t, raw, `"sequence": 1`, `"sequence": 999,"sequence": 1`)
	_, err = VerifyBundleV2(seqDup, fp)
	wantRejectMsg(t, err, RejectSchemaInvalid, "duplicate sequence")

	// Target-binding field: a second "assignment_id" inside the assignment object.
	aidDup := bytesReplaceOnce(t, raw, `"assignment_id": "assign-0001"`, `"assignment_id": "assign-evil","assignment_id": "assign-0001"`)
	_, err = VerifyBundleV2(aidDup, fp)
	wantRejectMsg(t, err, RejectSchemaInvalid, "duplicate assignment_id")

	// Target scope is also part of the signed binding.
	scopeDup := bytesReplaceOnce(t, raw, `"scope": "node"`, `"scope": "fleet","scope": "node"`)
	_, err = VerifyBundleV2(scopeDup, fp)
	wantRejectMsg(t, err, RejectSchemaInvalid, "duplicate target scope")
}

// (5b) target.node_id must be bound to scope: a fleet assignment must carry no
// node_id, a node assignment must carry one, so a signed bundle names exactly
// one unambiguous target. The fixture is node-scoped with a real node_id and
// stays valid; fleet+empty stays valid; only fleet+non-empty is rejected.
func TestV2_FleetScopeRejectsNodeID(t *testing.T) {
	_, fp := loadFixtureV2(t)

	// fleet + stray node_id -> rejected.
	bad := remarshalV2(t, func(b *PolicyBundleV2) {
		b.Policy.Assignment.Target.Scope = "fleet"
		b.Policy.Assignment.Target.NodeID = "node-east-1"
	})
	_, err := VerifyBundleV2(bad, fp)
	wantRejectMsg(t, err, RejectSchemaInvalid, "fleet scope with node_id")

	// fleet + empty node_id is structurally valid (it fails later at the hash
	// recompute, not at the scope/node_id check, which is the contract we assert).
	fleetOK := remarshalV2(t, func(b *PolicyBundleV2) {
		b.Policy.Assignment.Target.Scope = "fleet"
		b.Policy.Assignment.Target.NodeID = ""
	})
	_, err = VerifyBundleV2(fleetOK, fp)
	wantReject(t, err, RejectHashMismatch)

	// node + non-empty node_id is structurally valid (the fixture's own shape);
	// the no-op remarshal still passes scope/node_id and verifies end to end.
	nodeOK := remarshalV2(t, func(b *PolicyBundleV2) {})
	if _, err := VerifyBundleV2(nodeOK, fp); err != nil {
		t.Fatalf("node scope with node_id must stay valid: %v", err)
	}

	// node + empty node_id -> rejected.
	nodeBad := remarshalV2(t, func(b *PolicyBundleV2) {
		b.Policy.Assignment.Target.Scope = "node"
		b.Policy.Assignment.Target.NodeID = ""
	})
	_, err = VerifyBundleV2(nodeBad, fp)
	wantRejectMsg(t, err, RejectSchemaInvalid, "node scope without node_id")
}

// (6) trailing JSON after the bundle -> reject.
func TestV2_TrailingJSON(t *testing.T) {
	raw, fp := loadFixtureV2(t)
	withTrailing := append(append([]byte{}, raw...), []byte("\n{}\n")...)
	_, err := VerifyBundleV2(withTrailing, fp)
	wantReject(t, err, RejectDecode)
}

// (7) trust fingerprint mismatch -> reject.
func TestV2_WrongTrustFingerprint(t *testing.T) {
	raw, _ := loadFixtureV2(t)
	other := publicKeyFingerprint(make(ed25519.PublicKey, ed25519.PublicKeySize))
	_, err := VerifyBundleV2(raw, other)
	wantReject(t, err, RejectSigningKeyMismatch)
}

// Signature byte-flip remains a signature failure (self-consistent shape).
func TestV2_SignatureMismatch(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) {
		sig, _ := base64.StdEncoding.DecodeString(b.Signature.Value)
		sig[0] ^= 0xff
		b.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	})
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectSignatureInvalid)
}

// Self-inconsistent embedded key vs claimed fingerprint.
func TestV2_SelfInconsistentKey(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) {
		b.Signature.PublicKeyFingerprint = publicKeyFingerprint(make(ed25519.PublicKey, ed25519.PublicKeySize))
	})
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectUnsupportedBundle)
}

// (8) schema_version mismatch both directions, via dispatch and via the typed
// verifiers directly.
func TestV2_SchemaVersionMismatchBothDirections(t *testing.T) {
	v1raw, v1fp := loadFixture(t)
	v2raw, v2fp := loadFixtureV2(t)

	// v1 body to the v2 verifier -> schema invalid (constant tag check).
	_, err := VerifyBundleV2(v1raw, v1fp)
	wantRejectMsg(t, err, RejectSchemaInvalid, "v1 body to v2 verifier")

	// v2 body to the v1 verifier -> rejected. The v1 verifier's strict decode
	// (DisallowUnknownFields) trips on the v2-only "assignment" field before the
	// schema-constant check runs, so this surfaces as policy_decode. Either way
	// a v2 body is never accepted by the v1 verifier, which is the contract.
	_, err = VerifyBundle(v2raw, v2fp)
	wantRejectMsg(t, err, RejectDecode, "v2 body to v1 verifier")

	// Dispatch routes each to the right verifier and accepts both.
	r1, err := Verify(v1raw, v1fp)
	if err != nil {
		t.Fatalf("dispatch v1: %v", err)
	}
	if r1.SchemaVersion != SchemaVersion || r1.V1 == nil || r1.V2 != nil {
		t.Fatalf("dispatch v1 result wrong: %+v", r1)
	}
	r2, err := Verify(v2raw, v2fp)
	if err != nil {
		t.Fatalf("dispatch v2: %v", err)
	}
	if r2.SchemaVersion != SchemaVersionV2 || r2.V2 == nil || r2.V1 != nil {
		t.Fatalf("dispatch v2 result wrong: %+v", r2)
	}
}

// Dispatch rejects an unknown schema_version.
func TestV2_DispatchUnknownSchema(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.SchemaVersion = "policy_bundle.v9" })
	_, err := Verify(raw, fp)
	wantReject(t, err, RejectUnsupportedBundle)
}

// (9) assignment fields covered by the signed artifact: mutating assignment_id
// fails verification. assignment_id is bound by BOTH the body hash (it lives in
// the signed body) and the signing payload, so the hash recompute (step 4)
// catches the edit before the signature check (step 8) runs. The point of the
// test is coverage: the edit cannot pass, and it is the hash that proves it.
func TestV2_AssignmentIDCovered(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.AssignmentID = "assign-9999" })
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

// (10) target fields covered: mutating target.node_id fails. node_id is in the
// signed body, so the hash recompute catches it first.
func TestV2_TargetNodeIDCovered(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.Target.NodeID = "node-west-9" })
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

// (11) sequence covered: mutating sequence fails. sequence is in the signed
// body, so the hash recompute catches it first.
func TestV2_SequenceCovered(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.Sequence = 2 })
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

// To prove the SIGNING PAYLOAD independently binds the assignment metadata
// (not just the body hash), re-sign a body whose hash matches but whose payload
// binding is wrong: keep the body's assignment_id but sign a payload with a
// different assignment_id. The hash passes, the signature fails. This is the
// guarantee a store cannot satisfy by recomputing the hash after rewriting the
// binding.
func TestV2_AssignmentBoundInSigningPayload(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw, _ := loadFixtureV2(t)
	var b PolicyBundleV2
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Recompute the real body hash (unchanged body), then sign a payload that
	// claims a different assignment_id. A verifier that only checked the body
	// hash would accept this; ours must not.
	computed, _, err := policyHashHexV2(b.Policy)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	b.PolicyHash = computed
	// We cannot re-sign without the private key, so assert directly that the
	// real signature does NOT verify over a payload with a mutated binding (a
	// different assignment_id). A verifier that bound the assignment only via
	// the body hash would miss this; ours binds it in the signing payload too.
	badPayload := policyBundleV2SigningPayload(
		b.Policy.PolicyID, b.Policy.PolicyVersion, b.PolicyHash,
		"assign-DIFFERENT", b.Policy.Assignment.Target.Scope,
		b.Policy.Assignment.Target.NodeID, b.Policy.Assignment.IssuedAt,
		b.Policy.Assignment.Sequence, b.Policy.Assignment.RollbackOf,
		b.Signature.KeyID, b.Signature.PublicKeyFingerprint)
	pub, _ := base64.StdEncoding.DecodeString(b.Signature.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(b.Signature.Value)
	if ed25519.Verify(ed25519.PublicKey(pub), badPayload, sig) {
		t.Fatal("signature must NOT verify over a payload with a rewritten assignment_id")
	}
	_ = fp
}

func TestV2_IssuedAtCovered(t *testing.T) {
	_, fp := loadFixtureV2(t)
	// issued_at is in the body (hashed) AND in the signing payload. A canonical
	// change is caught by the hash recompute first.
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.IssuedAt = "2030-01-01T00:00:00Z" })
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

// (12) verifier does NOT normalize timestamp bytes before hashing: a
// non-canonical-but-parseable timestamp is rejected at the canonical-form
// check, before the hash. Covers created_at, issued_at, and signed_at.
// signed_at is not bound by the v2 signature (v2 binds issued_at), so without
// this check a malformed signed_at would ride through to a verified bundle; the
// canonical-form check is what stops it.
func TestV2_NonCanonicalTimestampsRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	for _, ts := range nonCanonicalTimestamps {
		rawC := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Metadata.CreatedAt = ts })
		_, err := VerifyBundleV2(rawC, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "created_at "+ts)

		rawI := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.IssuedAt = ts })
		_, err = VerifyBundleV2(rawI, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "issued_at "+ts)

		rawS := remarshalV2(t, func(b *PolicyBundleV2) { b.Signature.SignedAt = ts })
		_, err = VerifyBundleV2(rawS, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "signed_at "+ts)
	}
}

// (13) "merge" as a DimMode -> rejected as out-of-range enum (deferred in 9A).
func TestV2_MergeModeRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	cases := map[string]func(*PolicyBundleV2){
		"rules":                  func(b *PolicyBundleV2) { b.Policy.Rules.Mode = "merge" },
		"gateway":                func(b *PolicyBundleV2) { b.Policy.Gateway.Mode = "merge" },
		"egress":                 func(b *PolicyBundleV2) { b.Policy.Egress.Mode = "merge" },
		"redaction":              func(b *PolicyBundleV2) { b.Policy.Redaction.Mode = "merge" },
		"governance.server":      func(b *PolicyBundleV2) { b.Policy.Governance.Server.Mode = "merge" },
		"agent.acls":             func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ACLs.Mode = "merge" },
		"agent.tool_policies":    func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolPolicies.Mode = "merge" },
		"agent.tool_constraints": func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolConstraints.Mode = "merge" },
	}
	for name, mut := range cases {
		raw := remarshalV2(t, mut)
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "merge "+name)
	}
}

// Other dimension modes outside the set are also rejected.
func TestV2_InvalidDimModeRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Rules.Mode = "overwrite" })
	_, err := VerifyBundleV2(raw, fp)
	wantReject(t, err, RejectSchemaInvalid)
}

// (14) a container present as null/omitted -> rejected. Covers top-level and
// nested per-agent governance containers.
func TestV2_NullContainersRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	cases := map[string]func(*PolicyBundleV2){
		"rules.overrides":        func(b *PolicyBundleV2) { b.Policy.Rules.Overrides = nil },
		"gateway.tools_allowed":  func(b *PolicyBundleV2) { b.Policy.Gateway.ToolsAllowed = nil },
		"egress.domains_denied":  func(b *PolicyBundleV2) { b.Policy.Egress.DomainsDenied = nil },
		"governance.agents":      func(b *PolicyBundleV2) { b.Policy.Governance.Agents = nil },
		"agent.selector.labels":  func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Selector.Labels = nil },
		"agent.acls.allowed":     func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ACLs.AllowedRecipients = nil },
		"agent.allowed_tools":    func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].AllowedTools.Values = nil },
		"agent.tool_policies":    func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolPolicies.ByTool = nil },
		"agent.tool_constraints": func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolConstraints.Items = nil },
		"agent.tool_chain_rules": func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolChainRules.Items = nil },
		"agent.blocked_content":  func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].BlockedContent.Values = nil },
		"constraint.parameters":  func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters = nil },
		"constraint.param.allowed_patterns": func(b *PolicyBundleV2) {
			p := b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters["number"]
			p.AllowedPatterns = nil
			b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters["number"] = p
		},
		"constraint.param.blocked_patterns": func(b *PolicyBundleV2) {
			p := b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters["number"]
			p.BlockedPatterns = nil
			b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters["number"] = p
		},
		"chainrule.then":             func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].ToolChainRules.Items[0].Then = nil },
		"agent.egress.allowed":       func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Egress.AllowedDomains = nil },
		"agent.egress.blocked":       func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Egress.BlockedDomains = nil },
		"agent.egress.tool_restrict": func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Egress.ToolRestrictions = nil },
		"agent.egress.categories":    func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Egress.BlockedCategories = nil },
		"agent.egress.integrations":  func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Egress.Integrations = nil },
		"agent.egress.tool_restrict.entry": func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].Egress.ToolRestrictions["voice.dial"] = nil
		},
	}
	for name, mut := range cases {
		raw := remarshalV2(t, mut)
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "null "+name)
	}
}

// (15) sequence < 1 -> rejected.
func TestV2_SequenceBelowOneRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	for _, seq := range []int64{0, -1, -100} {
		raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.Sequence = seq })
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "sequence")
	}
}

// (16) target.scope outside {fleet,node} -> rejected.
func TestV2_InvalidTargetScopeRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	for _, scope := range []string{"", "cluster", "global", "Node"} {
		raw := remarshalV2(t, func(b *PolicyBundleV2) { b.Policy.Assignment.Target.Scope = scope })
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "scope "+scope)
	}
}

// Required scalar fields rejected when empty.
func TestV2_RequiredScalarsRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	cases := map[string]func(*PolicyBundleV2){
		"policy_id":      func(b *PolicyBundleV2) { b.Policy.PolicyID = "" },
		"policy_version": func(b *PolicyBundleV2) { b.Policy.PolicyVersion = "" },
		"assignment_id":  func(b *PolicyBundleV2) { b.Policy.Assignment.AssignmentID = "" },
		"created_by":     func(b *PolicyBundleV2) { b.Policy.Metadata.CreatedBy = "" },
		"reason":         func(b *PolicyBundleV2) { b.Policy.Metadata.Reason = "" },
		"key_id":         func(b *PolicyBundleV2) { b.Signature.KeyID = "" },
		"agent.selector": func(b *PolicyBundleV2) { b.Policy.Governance.Agents[0].Selector.Name = "" },
	}
	for name, mut := range cases {
		raw := remarshalV2(t, mut)
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "empty "+name)
	}
}

// Non-canonical decimal strings in a tool policy are rejected.
func TestV2_NonCanonicalDecimalRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	bad := []string{"1,000.00", "100.", "+5", "0x10", "1e3", " 5", "abc", "01.5"}
	for _, v := range bad {
		raw := remarshalV2(t, func(b *PolicyBundleV2) {
			tp := b.Policy.Governance.Agents[0].ToolPolicies.ByTool["voice.dial"]
			tp.MaxAmount = v
			b.Policy.Governance.Agents[0].ToolPolicies.ByTool["voice.dial"] = tp
		})
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "decimal "+v)
	}
}

// empty trust fingerprint is a usage error on both the v2 verifier and dispatch.
func TestV2_EmptyTrustIsUsageError(t *testing.T) {
	raw, _ := loadFixtureV2(t)
	if _, err := VerifyBundleV2(raw, ""); !errors.Is(err, ErrTrustFingerprintRequired) {
		t.Fatalf("v2 empty trust must be usage error, got %v", err)
	}
	if _, err := Verify(raw, ""); !errors.Is(err, ErrTrustFingerprintRequired) {
		t.Fatalf("dispatch empty trust must be usage error, got %v", err)
	}
}

// TestV2_SigningPayloadStable locks the cross-repo byte layout of the v2
// signing payload. The signer and this verifier must agree exactly.
func TestV2_SigningPayloadStable(t *testing.T) {
	got := string(policyBundleV2SigningPayload(
		"voice-ai-prod", "1", "sha256:abc",
		"assign-0001", "node", "node-east-1", "2026-01-01T00:00:00Z",
		1, "", "kid", "sha256:fp"))
	want := "oktsec.policy_bundle.v2\n" +
		"bundle_version:2\n" +
		"policy_id:voice-ai-prod\n" +
		"policy_version:1\n" +
		"policy_hash:sha256:abc\n" +
		"canonicalization:oktsec-policy-v2-typed-utc-json\n" +
		"assignment_id:assign-0001\n" +
		"target_scope:node\n" +
		"target_node_id:node-east-1\n" +
		"issued_at:2026-01-01T00:00:00Z\n" +
		"sequence:1\n" +
		"rollback_of:\n" +
		"signature_key_id:kid\n" +
		"signature_public_key_fingerprint:sha256:fp"
	if got != want {
		t.Fatalf("v2 signing payload layout drift:\n got=%q\nwant=%q", got, want)
	}
}

// Map determinism: re-encoding the body with shuffled-in map entries produces
// the same canonical bytes (encoding/json sorts map keys), so the hash is
// stable across map insertion order.
func TestV2_MapCanonicalizationDeterministic(t *testing.T) {
	raw, _ := loadFixtureV2(t)
	var b PolicyBundleV2
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	h1, _, err := policyHashHexV2(b.Policy)
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	// Rebuild the labels map in a different insertion order.
	old := b.Policy.Governance.Agents[0].Selector.Labels
	reordered := map[string]string{}
	keys := []string{"tier", "env"}
	for _, k := range keys {
		reordered[k] = old[k]
	}
	b.Policy.Governance.Agents[0].Selector.Labels = reordered
	h2, _, err := policyHashHexV2(b.Policy)
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("map insertion order changed the hash: %s != %s", h1, h2)
	}
}

// Per-agent egress dimension mode: unmanaged/replace/clear are all accepted at
// the verify level (apply semantics are 9A.2; the verifier only validates the
// closed-set mode). The fixture carries egress in "replace" mode; switching the
// mode keeps the bundle structurally valid through the egress check, so it fails
// later at the hash recompute, which is the contract this asserts.
func TestV2_AgentEgressModeAccepted(t *testing.T) {
	_, fp := loadFixtureV2(t)
	for _, mode := range []string{"unmanaged", "replace", "clear"} {
		raw := remarshalV2(t, func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].Egress.Mode = mode
		})
		// A no-op remarshal that keeps "replace" (the fixture's mode) must verify
		// end to end; the other two change the body, so the hash recompute (a
		// later check than the egress mode validation) catches them. Either way
		// the egress mode check itself accepts the value (no schema reject).
		_, err := VerifyBundleV2(raw, fp)
		if mode == "replace" {
			if err != nil {
				t.Fatalf("egress mode %q must verify end to end: %v", mode, err)
			}
			continue
		}
		wantReject(t, err, RejectHashMismatch)
	}
}

// Per-agent egress scan_requests/scan_responses are a closed-set tri-state
// string ("unset"|"true"|"false"). An out-of-set value is a schema reject,
// before the bundle is labeled verified.
func TestV2_AgentEgressTriStateRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	bad := []string{"", "yes", "True", "1", "null", "maybe"}
	for _, v := range bad {
		rawReq := remarshalV2(t, func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].Egress.ScanRequests = v
		})
		_, err := VerifyBundleV2(rawReq, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "scan_requests "+v)

		rawResp := remarshalV2(t, func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].Egress.ScanResponses = v
		})
		_, err = VerifyBundleV2(rawResp, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "scan_responses "+v)
	}
}

// Negative monetary/limit decimal strings in a tool policy are rejected: the
// runtime treats a non-positive limit as unset, so a verified bundle must not
// carry a negative limit (it would silently disable the limit if applied).
func TestV2_NegativeDecimalRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	fields := []struct {
		name string
		set  func(*ToolPolicyV2, string)
	}{
		{"max_amount", func(tp *ToolPolicyV2, v string) { tp.MaxAmount = v }},
		{"daily_limit", func(tp *ToolPolicyV2, v string) { tp.DailyLimit = v }},
		{"require_approval_above", func(tp *ToolPolicyV2, v string) { tp.RequireApprovalAbove = v }},
	}
	for _, f := range fields {
		raw := remarshalV2(t, func(b *PolicyBundleV2) {
			tp := b.Policy.Governance.Agents[0].ToolPolicies.ByTool["voice.dial"]
			f.set(&tp, "-1")
			b.Policy.Governance.Agents[0].ToolPolicies.ByTool["voice.dial"] = tp
		})
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "negative "+f.name)
	}
}

// Negative integer guardrails across the agent surface are rejected: the
// runtime activates these only when positive, so a signed negative value would
// fail open if applied. Covers tool_policies.rate_limit, tool_constraints
// max_response_bytes/cooldown_secs/parameters.max_length,
// tool_chain_rules.cooldown_secs, and per-agent egress rate_limit/rate_window.
func TestV2_NegativeIntGuardrailsRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	cases := map[string]func(*PolicyBundleV2){
		"tool_policy.rate_limit": func(b *PolicyBundleV2) {
			tp := b.Policy.Governance.Agents[0].ToolPolicies.ByTool["voice.dial"]
			tp.RateLimit = -1
			b.Policy.Governance.Agents[0].ToolPolicies.ByTool["voice.dial"] = tp
		},
		"constraint.max_response_bytes": func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].ToolConstraints.Items[0].MaxResponseBytes = -1
		},
		"constraint.cooldown_secs": func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].ToolConstraints.Items[0].CooldownSecs = -1
		},
		"param.max_length": func(b *PolicyBundleV2) {
			pc := b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters["number"]
			pc.MaxLength = -1
			b.Policy.Governance.Agents[0].ToolConstraints.Items[0].Parameters["number"] = pc
		},
		"chainrule.cooldown_secs": func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].ToolChainRules.Items[0].CooldownSecs = -1
		},
		"egress.rate_limit": func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].Egress.RateLimit = -1
		},
		"egress.rate_window": func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].Egress.RateWindow = -1
		},
		"server.rate_limit_max": func(b *PolicyBundleV2) {
			b.Policy.Governance.Server.RateLimitMax = -1
		},
		"server.rate_limit_window_s": func(b *PolicyBundleV2) {
			b.Policy.Governance.Server.RateLimitWindow = -1
		},
	}
	for name, mut := range cases {
		raw := remarshalV2(t, mut)
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "negative "+name)
	}
}

// scan_profile.value is a closed set; an out-of-set value is a schema reject.
func TestV2_InvalidScanProfileRejected(t *testing.T) {
	_, fp := loadFixtureV2(t)
	for _, v := range []string{"off", "STRICT", "aggressive", "none"} {
		raw := remarshalV2(t, func(b *PolicyBundleV2) {
			b.Policy.Governance.Agents[0].ScanProfile.Value = v
		})
		_, err := VerifyBundleV2(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "scan_profile "+v)
	}
}

// The realigned tool_constraints / tool_chain_rules / per-agent egress fields
// round-trip through canonicalization deterministically: re-encoding the same
// body (including the egress.tool_restrictions and constraint.parameters maps in
// a different insertion order) yields the identical hash. This guards the
// config-aligned field names against accidental non-determinism.
func TestV2_RealignedFieldsCanonicalDeterministic(t *testing.T) {
	raw, _ := loadFixtureV2(t)
	var b PolicyBundleV2
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	h1, _, err := policyHashHexV2(b.Policy)
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	// Rebuild the egress tool_restrictions map fresh (different backing map, same
	// contents) and a constraint parameters map fresh.
	eg := &b.Policy.Governance.Agents[0].Egress
	rebuilt := map[string][]string{}
	for k, v := range eg.ToolRestrictions {
		rebuilt[k] = v
	}
	eg.ToolRestrictions = rebuilt
	c := &b.Policy.Governance.Agents[0].ToolConstraints.Items[0]
	rebuiltParams := map[string]ParamConstraintV2{}
	for k, v := range c.Parameters {
		rebuiltParams[k] = v
	}
	c.Parameters = rebuiltParams
	h2, _, err := policyHashHexV2(b.Policy)
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("realigned-field canonicalization not deterministic: %s != %s", h1, h2)
	}
}
