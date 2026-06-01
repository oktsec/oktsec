package node

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vendoredPolicyBundleV2 is a real, deterministically signed
// policy_bundle.v2 vendored verbatim from the policybundle package (the
// same artifact policybundle.VerifyBundleV2 verifies in its own tests).
// Embedding it here lets the node snapshot's v2 verification path exercise
// a genuine v2 bundle end to end, and guards the cross-package contract:
// if the snapshot dispatch or the v2 verifier drift, these tests fail.
//
//go:embed policy_bundle_v2_fixture.json
var vendoredPolicyBundleV2 []byte

// v2FixtureFingerprint returns the trust fingerprint the vendored v2
// fixture was signed with (its embedded signing-key fingerprint).
func v2FixtureFingerprint(t *testing.T) string {
	t.Helper()
	var b rawPolicyBundle
	if err := json.Unmarshal(vendoredPolicyBundleV2, &b); err != nil {
		t.Fatalf("decode v2 fixture: %v", err)
	}
	if b.Signature.PublicKeyFingerprint == "" {
		t.Fatal("v2 fixture has no signing-key fingerprint")
	}
	return b.Signature.PublicKeyFingerprint
}

// writeV2 drops raw v2 bundle bytes into a temp file and returns the path.
func writeV2(t *testing.T, raw []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.v2.signed.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("write v2 bundle: %v", err)
	}
	return p
}

// (1) Regression: the v1 path stays frozen. A v1 bundle signed with the
// node's own payload reconstruction still verifies true under its trust
// fingerprint, unchanged by the v2 dispatch.
func TestBuildPolicySection_V1StillVerifies(t *testing.T) {
	priv := newKey(t)
	trustFP := policyKeyFingerprint(priv.Public().(ed25519.PublicKey))
	path := writeV2(t, signedBundleJSON(t, priv, nil))
	sec, warns := buildPolicySection(path, trustFP)
	if len(warns) != 0 {
		t.Fatalf("valid v1 bundle must not warn, got %v", warns)
	}
	if !sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationVerified {
		t.Fatalf("v1 path drifted: verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
	}
	if sec.PolicyStatus != PolicyStatusActive {
		t.Fatalf("status = %q, want %q", sec.PolicyStatus, PolicyStatusActive)
	}
}

// (2) A valid v2 bundle + matching trust fingerprint verifies true, and
// the reported hash/id/version come from the v2 body.
func TestBuildPolicySection_V2Verified(t *testing.T) {
	trustFP := v2FixtureFingerprint(t)
	path := writeV2(t, vendoredPolicyBundleV2)
	sec, warns := buildPolicySection(path, trustFP)
	if len(warns) != 0 {
		t.Fatalf("valid v2 bundle must not warn, got %v", warns)
	}
	if !sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationVerified {
		t.Fatalf("v2 bundle did not verify: verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
	}
	if sec.PolicyStatus != PolicyStatusActive {
		t.Fatalf("status = %q, want %q", sec.PolicyStatus, PolicyStatusActive)
	}
	// Identity comes from the v2 body (echoed via the tolerant projection,
	// which reads the same JSON paths the v2 envelope uses).
	if sec.ActivePolicyHash != "sha256:304e887278c6d571daa9e2b4e68aa4e41fee9850e837196da27d97845de95cf2" {
		t.Errorf("hash = %q, want v2 body hash", sec.ActivePolicyHash)
	}
	if sec.ActivePolicyID != "voice-ai-prod" {
		t.Errorf("id = %q, want v2 body policy_id", sec.ActivePolicyID)
	}
	if sec.ActivePolicyVersion != "1" {
		t.Errorf("version = %q, want v2 body policy_version", sec.ActivePolicyVersion)
	}
}

// (3) Wrong trust fingerprint on a valid v2 bundle -> verified false,
// signing_key_mismatch (same status the v1 path uses for this case).
func TestBuildPolicySection_V2WrongTrustFingerprint(t *testing.T) {
	otherFP := policyKeyFingerprint(newKey(t).Public().(ed25519.PublicKey))
	path := writeV2(t, vendoredPolicyBundleV2)
	sec, _ := buildPolicySection(path, otherFP)
	if sec.ActivePolicyVerified {
		t.Fatal("v2 bundle must not verify under a wrong trust fingerprint")
	}
	if sec.ActivePolicyVerificationStatus != PolicyVerificationSigningKeyMismatch {
		t.Fatalf("status = %q, want %q", sec.ActivePolicyVerificationStatus, PolicyVerificationSigningKeyMismatch)
	}
}

// (4) A v2 bundle corrupted after signing (its declared policy_hash
// flipped) fails closed. The hash no longer matches the body the
// signature covers, so VerifyBundleV2 rejects it; the node reports
// signature_invalid (fail closed, never verified). A separate case
// corrupts the schema body so the strict v2 decode rejects it as
// unsupported_bundle.
func TestBuildPolicySection_V2FailClosed(t *testing.T) {
	trustFP := v2FixtureFingerprint(t)

	t.Run("hash_flipped_signature_invalid", func(t *testing.T) {
		var m map[string]any
		if err := json.Unmarshal(vendoredPolicyBundleV2, &m); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		m["policy_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		sec, _ := buildPolicySection(writeV2(t, raw), trustFP)
		if sec.ActivePolicyVerified {
			t.Fatal("corrupted v2 bundle must not verify")
		}
		if sec.ActivePolicyVerificationStatus != PolicyVerificationSignatureInvalid {
			t.Fatalf("status = %q, want %q", sec.ActivePolicyVerificationStatus, PolicyVerificationSignatureInvalid)
		}
	})

	t.Run("unknown_field_unsupported", func(t *testing.T) {
		// A v2-tagged bundle carrying an unknown top-level field is
		// rejected by the strict v2 decode (policy_decode) and reported
		// as unsupported_bundle, never verified.
		var m map[string]any
		if err := json.Unmarshal(vendoredPolicyBundleV2, &m); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		m["unexpected_field"] = "x"
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		sec, _ := buildPolicySection(writeV2(t, raw), trustFP)
		if sec.ActivePolicyVerified {
			t.Fatal("malformed v2 bundle must not verify")
		}
		if sec.ActivePolicyVerificationStatus != PolicyVerificationUnsupportedBundle {
			t.Fatalf("status = %q, want %q", sec.ActivePolicyVerificationStatus, PolicyVerificationUnsupportedBundle)
		}
	})
}

// (5) Supports the 9A.4 smoke: a present v2 bundle with NO trust
// fingerprint is reported present-but-unverified as no_trust_anchor, the
// same status the v1 path uses, so the smoke can distinguish "no anchor"
// from "verified". Identity is still echoed (the bundle IS present).
func TestBuildPolicySection_V2NoTrustAnchor(t *testing.T) {
	path := writeV2(t, vendoredPolicyBundleV2)
	sec, warns := buildPolicySection(path, "")
	if len(warns) != 0 {
		t.Fatalf("present v2 bundle must not warn, got %v", warns)
	}
	if sec.ActivePolicyVerified {
		t.Fatal("no trust anchor means not verified")
	}
	if sec.ActivePolicyVerificationStatus != PolicyVerificationNoTrustAnchor {
		t.Fatalf("status = %q, want %q", sec.ActivePolicyVerificationStatus, PolicyVerificationNoTrustAnchor)
	}
	if sec.PolicyStatus != PolicyStatusActive {
		t.Fatalf("status = %q, want %q (bundle is present)", sec.PolicyStatus, PolicyStatusActive)
	}
	if sec.ActivePolicyID != "voice-ai-prod" || sec.ActivePolicyVersion != "1" {
		t.Fatalf("identity not echoed for present-but-unverified v2: id=%q version=%q", sec.ActivePolicyID, sec.ActivePolicyVersion)
	}
}
