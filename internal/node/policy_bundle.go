package node

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/policybundle"
	"github.com/oktsec/oktsec/internal/safefile"
)

// maxPolicyBundleBytes caps how much of a --policy-bundle file the
// snapshot reads. Policy bundles are small signed JSON documents; the
// cap keeps a planted multi-gigabyte file from stalling a snapshot.
const maxPolicyBundleBytes = 1 << 20 // 1 MiB

// Frozen constants of the policy_bundle.v1 signing contract this node
// verifies. Order 4C.1 verifies a bundle's signature locally, which
// means reproducing the exact signing payload the bundle signer
// covered. These values are part of that contract: a drift here
// surfaces as a broken signature on every bundle, which is the right
// failure mode. A vendored signed fixture (testdata) guards the format
// against silent divergence.
const (
	policyBundleSchemaVersion    = "policy_bundle.v1"
	policyBundleVersion          = 1
	policyBundleCanonicalization = "oktsec-policy-v1-typed-utc-json"
	policyBundleSignatureAlg     = "Ed25519"
)

// rawPolicyBundle is the tolerant projection of a signed policy_bundle.v1
// the snapshot needs. This node does not own the bundle contract, so the
// decode stays tolerant (no DisallowUnknownFields). Order 4C.1 added the
// signature block + canonicalization tag so the node can verify the
// signature locally; the field names follow the policy_bundle.v1 shape.
type rawPolicyBundle struct {
	SchemaVersion    string `json:"schema_version"`
	BundleVersion    int    `json:"bundle_version"`
	PolicyHash       string `json:"policy_hash"`
	Canonicalization string `json:"canonicalization"`
	Policy           struct {
		PolicyID      string `json:"policy_id"`
		PolicyVersion string `json:"policy_version"`
		// Assignment is the v2 signed assignment binding. Read via the
		// tolerant projection but echoed by buildPolicySection ONLY when
		// schema_version is policy_bundle.v2 (the v1 signing payload does
		// not bind it, so it is not trustworthy on a v1 bundle). Only
		// assignment_id + sequence are read; the snapshot echoes them so
		// a verifier can compare the exact assignment, not just the hash
		// (Order 9B).
		Assignment struct {
			AssignmentID string `json:"assignment_id"`
			Sequence     int64  `json:"sequence"`
		} `json:"assignment"`
	} `json:"policy"`
	Signature struct {
		Alg                  string `json:"alg"`
		KeyID                string `json:"key_id"`
		PublicKey            string `json:"public_key"`
		PublicKeyFingerprint string `json:"public_key_fingerprint"`
		SignedAt             string `json:"signed_at"`
		Value                string `json:"value"`
	} `json:"signature"`
}

// buildPolicySection produces the additive Order 4B policy block from
// the supplied --policy-bundle path, with Order 4C.1 verification.
//
// Verification (4C.1) is signature-only: the node verifies the Ed25519
// signature over the declared policy hash against the bundle's embedded
// public key, and that the embedded key's fingerprint matches the
// operator-configured trust fingerprint. It does NOT recompute the
// policy body hash and does NOT apply the policy — "verified" means
// exactly "signature over the declared policy hash verified", nothing
// more. ActivePolicyVerificationStatus reports which check decided it.
//
// Returned block is never nil for a 4B+ node — the none case is an
// explicit PolicyStatusNone block, not an absent one.
func buildPolicySection(bundlePath, trustFingerprint string) (*SnapshotPolicy, []Warning) {
	if bundlePath == "" {
		return &SnapshotPolicy{
			ActivePolicySource:   PolicySourceNone,
			ActivePolicyVerified: false,
			PolicyStatus:         PolicyStatusNone,
		}, nil
	}

	unreadable := func(msg string) (*SnapshotPolicy, []Warning) {
		return &SnapshotPolicy{
				ActivePolicySource:             PolicySourceLocalFile,
				ActivePolicyVerified:           false,
				ActivePolicyVerificationStatus: PolicyVerificationBundleUnreadable,
				PolicyStatus:                   PolicyStatusUnreadable,
			}, []Warning{{
				Code:    WarnPolicyBundleUnreadable,
				Message: "Policy bundle could not be read as a declared active policy: " + msg,
			}}
	}

	// RejectSymlink uses Lstat, so this also catches a missing path
	// or a path the node cannot stat — the err text disambiguates the
	// symlink case from the not-found case.
	if err := safefile.RejectSymlink(bundlePath); err != nil {
		return unreadable("path not usable: " + err.Error())
	}
	data, err := safefile.ReadFileMax(bundlePath, maxPolicyBundleBytes)
	if err != nil {
		return unreadable("read failed: " + err.Error())
	}
	var bundle rawPolicyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return unreadable("invalid JSON: " + err.Error())
	}
	// A bundle that does not declare the minimal identity a verifier
	// compares against (hash + id) is not a usable active policy. This
	// tolerant projection shares the policy_hash / policy.policy_id /
	// policy.policy_version JSON paths with both the v1 and v2 envelopes,
	// so the minimal-identity guard is schema-agnostic.
	if bundle.PolicyHash == "" {
		return unreadable("bundle declares no policy_hash")
	}
	if bundle.Policy.PolicyID == "" {
		return unreadable("bundle declares no policy.policy_id")
	}

	// Dispatch verification by the declared schema_version. v1 (and any
	// legacy/unknown shape) keeps the byte-for-byte Order 4C.1 path; v2
	// reuses the already-merged policybundle.VerifyBundleV2 verifier. The
	// reported hash/id/version always come from the tolerant projection
	// above, which reads the same JSON paths for both schemas.
	var verified bool
	var status string
	var assignmentID string
	var appliedSeq int64
	if bundle.SchemaVersion == policybundle.SchemaVersionV2 {
		verified, status = verifyPolicyBundleV2(data, trustFingerprint)
		// Echo the assignment binding ONLY for v2: the v2 signing payload
		// binds policy.assignment, so it is covered by the same signature
		// ActivePolicyVerified reflects. The v1 signing payload does NOT bind
		// assignment, so a v1 bundle with an injected policy.assignment object
		// still verifies under v1 — echoing it would present forged, unsigned
		// assignment metadata next to verified=true. Leave the fields absent
		// for v1/legacy/unknown schemas regardless of what the JSON carries.
		assignmentID = bundle.Policy.Assignment.AssignmentID
		appliedSeq = bundle.Policy.Assignment.Sequence
	} else {
		verified, status = verifyPolicyBundle(bundle, trustFingerprint)
	}
	return &SnapshotPolicy{
		ActivePolicyHash:               bundle.PolicyHash,
		ActivePolicyID:                 bundle.Policy.PolicyID,
		ActivePolicyVersion:            bundle.Policy.PolicyVersion,
		ActivePolicySource:             PolicySourceLocalFile,
		ActivePolicyLoadedAt:           policyBundleLoadedAt(bundlePath),
		ActivePolicyVerified:           verified,
		ActivePolicyVerificationStatus: status,
		AppliedAssignmentID:            assignmentID,
		AppliedSequence:                appliedSeq,
		PolicyStatus:                   PolicyStatusActive,
	}, nil
}

// verifyPolicyBundleV2 runs the Order 9A.4.1 signature verification for a
// policy_bundle.v2 bundle, reusing the merged policybundle.VerifyBundleV2
// verifier. It maps the result into the SAME ActivePolicyVerificationStatus
// vocabulary the v1 path uses; no new status strings are introduced.
//
// As with v1, "verified" means exactly "the Ed25519 signature over the v2
// signing payload verified against the operator-configured trust
// fingerprint". The body is not applied here.
//
// Trust-anchor handling mirrors v1's ordering exactly: shape/structure
// FIRST, then the no-trust-anchor decision, then signature verification.
// VerifyBundleV2 entangles the trust match with its shape checks (it
// rejects an empty trust fingerprint outright), so the no-anchor case
// cannot pass it the empty fingerprint directly. To keep the reported
// status accurate even without a configured trust anchor, the
// empty-fingerprint case runs the SAME strict v2 verification against the
// bundle's OWN embedded key fingerprint. That reuses every shape, schema,
// duplicate-key, hash, and signature check VerifyBundleV2 performs (its
// trust-match step trivially passes because the embedded key is its own
// self-consistent fingerprint), without reimplementing any of them:
//
//	verifier rejects (malformed/unsupported/bad signature) -> the mapped
//	  reject status (unsupported_bundle / signature_invalid), EVEN WITH no
//	  configured trust anchor (fail closed)
//	verifier accepts (well-shaped AND self-signature valid) -> the only
//	  thing missing is the operator trust anchor -> no_trust_anchor
//
// So a bundle's snapshot status no longer flips between unsupported_bundle/
// signature_invalid and no_trust_anchor merely because a trust fingerprint
// is added: the structural verdict is identical either way, and the trust
// anchor only decides verified vs signing_key_mismatch vs no_trust_anchor.
func verifyPolicyBundleV2(raw []byte, trustFingerprint string) (bool, string) {
	if trustFingerprint == "" {
		// Shape/structure first, via the real verifier against the bundle's
		// own embedded fingerprint, then the no-trust-anchor decision.
		ownFP := embeddedV2Fingerprint(raw)
		if ownFP == "" {
			// No usable embedded fingerprint to anchor the self-check on:
			// the signature block is malformed, so fail closed.
			return false, PolicyVerificationUnsupportedBundle
		}
		if _, err := policybundle.VerifyBundleV2(raw, ownFP); err != nil {
			return false, policyV2RejectToStatus(err)
		}
		return false, PolicyVerificationNoTrustAnchor
	}
	if _, err := policybundle.VerifyBundleV2(raw, trustFingerprint); err != nil {
		return false, policyV2RejectToStatus(err)
	}
	return true, PolicyVerificationVerified
}

// embeddedV2Fingerprint returns the public_key_fingerprint a v2 bundle
// claims for its embedded signing key, used only to drive the no-anchor
// self-check through VerifyBundleV2 (which requires a non-empty trust
// fingerprint). It does NOT decide trust: VerifyBundleV2 still re-derives
// the fingerprint from the embedded key and rejects a self-inconsistent
// block, so a hand-edited fingerprint cannot launder a bad bundle. Returns
// "" when the claimed fingerprint is absent (the bundle is then treated as
// an unsupported shape, matching the verifier's own self-consistency
// reject).
func embeddedV2Fingerprint(raw []byte) string {
	var b rawPolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return ""
	}
	return b.Signature.PublicKeyFingerprint
}

// policyV2RejectToStatus maps a policybundle.VerifyBundleV2 reject code onto
// the existing ActivePolicyVerificationStatus vocabulary, mirroring how the
// v1 path classifies the equivalent failures. No new status strings.
//
//	policy_signing_key_mismatch -> signing_key_mismatch
//	policy_hash_mismatch        -> signature_invalid (the declared hash the
//	                               signature covers did not match the body)
//	policy_signature_invalid    -> signature_invalid
//	policy_decode / policy_schema_invalid / policy_unsupported_bundle
//	                            -> unsupported_bundle
//
// A non-reject error (none is expected from VerifyBundleV2 once the trust
// fingerprint is non-empty) falls back to unsupported_bundle so the node
// fails closed rather than claiming verification.
func policyV2RejectToStatus(err error) string {
	var re *policybundle.RejectError
	if !errors.As(err, &re) {
		return PolicyVerificationUnsupportedBundle
	}
	switch re.Code {
	case policybundle.RejectSigningKeyMismatch:
		return PolicyVerificationSigningKeyMismatch
	case policybundle.RejectHashMismatch, policybundle.RejectSignatureInvalid:
		return PolicyVerificationSignatureInvalid
	default:
		// policy_decode, policy_schema_invalid, policy_unsupported_bundle.
		return PolicyVerificationUnsupportedBundle
	}
}

// verifyPolicyBundle runs the Order 4C.1 verification state machine
// against a readable bundle. Check order is the contract:
//
//	unsupported signature shape         -> unsupported_bundle
//	no trust fingerprint configured     -> no_trust_anchor
//	embedded key fp != trust fingerprint-> signing_key_mismatch
//	signature does not verify           -> signature_invalid
//	all pass                            -> verified
//
// The signature covers policy_hash via the domain-separated payload,
// so a verified signature authenticates the reported hash. The body is
// NOT re-hashed here (that is 4C.2 apply territory).
func verifyPolicyBundle(b rawPolicyBundle, trustFingerprint string) (bool, string) {
	sig := b.Signature
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	switch {
	case b.SchemaVersion != policyBundleSchemaVersion,
		b.BundleVersion != policyBundleVersion,
		b.Canonicalization != policyBundleCanonicalization,
		sig.Alg != policyBundleSignatureAlg,
		sig.Value == "",
		err != nil,
		len(pub) != ed25519.PublicKeySize:
		return false, PolicyVerificationUnsupportedBundle
	}
	// Self-consistency: the embedded key must hash to the fingerprint
	// the bundle claims for it. A mismatch means a malformed/hand-edited
	// signature block, not a trust decision — treat it as unsupported.
	derivedFP := policyKeyFingerprint(pub)
	if sig.PublicKeyFingerprint != "" && sig.PublicKeyFingerprint != derivedFP {
		return false, PolicyVerificationUnsupportedBundle
	}
	if trustFingerprint == "" {
		return false, PolicyVerificationNoTrustAnchor
	}
	if derivedFP != trustFingerprint {
		return false, PolicyVerificationSigningKeyMismatch
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false, PolicyVerificationSignatureInvalid
	}
	payload := policyBundleSigningPayload(
		b.Policy.PolicyID, b.Policy.PolicyVersion, b.PolicyHash,
		sig.SignedAt, sig.KeyID, sig.PublicKeyFingerprint)
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sigBytes) {
		return false, PolicyVerificationSignatureInvalid
	}
	return true, PolicyVerificationVerified
}

// policyBundleSigningPayload reproduces the exact bytes the
// policy_bundle.v1 signer covers. Domain-separated labeled lines,
// newline-joined, no trailing newline. MUST stay byte-identical to the
// signing contract or every bundle signature fails to verify.
func policyBundleSigningPayload(policyID, policyVersion, policyHash, signedAt, keyID, publicKeyFingerprint string) []byte {
	lines := []string{
		"oktsec." + policyBundleSchemaVersion,
		fmt.Sprintf("bundle_version:%d", policyBundleVersion),
		"policy_id:" + policyID,
		"policy_version:" + policyVersion,
		"policy_hash:" + policyHash,
		"canonicalization:" + policyBundleCanonicalization,
		"signed_at:" + signedAt,
		"signature_key_id:" + keyID,
		"signature_public_key_fingerprint:" + publicKeyFingerprint,
	}
	return []byte(strings.Join(lines, "\n"))
}

// policyKeyFingerprint is the policy_bundle.v1 key fingerprint format:
// the wire-format fingerprint of an Ed25519 public key, sha256:<64-hex>.
func policyKeyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// policyBundleLoadedAt returns the bundle file's modification time as
// UTC RFC3339 — when the bundle landed on the node, a staleness signal.
// Returns "" if the time cannot be read; the field is omitempty so an
// unknown mtime simply drops out of the JSON rather than emitting a
// misleading zero time.
func policyBundleLoadedAt(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}
