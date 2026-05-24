package node

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vendoredPolicyBundleV1 is a real policy_bundle.v1 produced by the
// upstream signer, embedded (not under the gitignored testdata/) so the
// cross-contract guard ships with the repo and runs in CI.
//
//go:embed policy_bundle_v1_fixture.json
var vendoredPolicyBundleV1 []byte

// signedBundleJSON builds a policy_bundle.v1 JSON signed by priv over
// the mirrored Enterprise signing payload. mutate lets a test corrupt
// a field after signing to exercise a failure path.
func signedBundleJSON(t *testing.T, priv ed25519.PrivateKey, mutate func(m map[string]any)) []byte {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	fp := policyKeyFingerprint(pub)
	const (
		id       = "voice-ai-prod"
		ver      = "1"
		hash     = "sha256:9f588db2911071e2f6a62042a2b66b184f6103a358d31481eb215bccdc993368"
		signedAt = "2026-05-22T00:00:00Z"
		keyID    = "enterprise-policy"
	)
	sig := ed25519.Sign(priv, policyBundleSigningPayload(id, ver, hash, signedAt, keyID, fp))
	m := map[string]any{
		"schema_version":   policyBundleSchemaVersion,
		"bundle_version":   policyBundleVersion,
		"policy_hash":      hash,
		"canonicalization": policyBundleCanonicalization,
		"policy":           map[string]any{"policy_id": id, "policy_version": ver},
		"signature": map[string]any{
			"alg":                    policyBundleSignatureAlg,
			"key_id":                 keyID,
			"public_key":             base64.StdEncoding.EncodeToString(pub),
			"public_key_fingerprint": fp,
			"signed_at":              signedAt,
			"value":                  base64.StdEncoding.EncodeToString(sig),
		},
	}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return priv
}

// TestBuildPolicySection_VerificationStates walks the Order 4C.1
// verification state machine. Each case writes a bundle, runs
// buildPolicySection with a trust fingerprint, and asserts the verdict.
func TestBuildPolicySection_VerificationStates(t *testing.T) {
	priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	trustFP := policyKeyFingerprint(pub)
	otherFP := policyKeyFingerprint(newKey(t).Public().(ed25519.PublicKey))

	write := func(raw []byte) string {
		dir := t.TempDir()
		p := filepath.Join(dir, "policy.signed.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return p
	}

	t.Run("verified", func(t *testing.T) {
		sec, _ := buildPolicySection(write(signedBundleJSON(t, priv, nil)), trustFP)
		if !sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationVerified {
			t.Fatalf("got verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("no_trust_anchor", func(t *testing.T) {
		sec, _ := buildPolicySection(write(signedBundleJSON(t, priv, nil)), "")
		if sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationNoTrustAnchor {
			t.Fatalf("got verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("signing_key_mismatch", func(t *testing.T) {
		sec, _ := buildPolicySection(write(signedBundleJSON(t, priv, nil)), otherFP)
		if sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationSigningKeyMismatch {
			t.Fatalf("got verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("signature_invalid", func(t *testing.T) {
		// Sign for the real fields, then change policy_hash so the
		// committed bytes no longer match the signature.
		raw := signedBundleJSON(t, priv, func(m map[string]any) {
			m["policy_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		})
		sec, _ := buildPolicySection(write(raw), trustFP)
		if sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationSignatureInvalid {
			t.Fatalf("got verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("unsupported_bundle_no_signature", func(t *testing.T) {
		raw := signedBundleJSON(t, priv, func(m map[string]any) { delete(m, "signature") })
		sec, _ := buildPolicySection(write(raw), trustFP)
		if sec.ActivePolicyVerified || sec.ActivePolicyVerificationStatus != PolicyVerificationUnsupportedBundle {
			t.Fatalf("got verified=%v status=%q", sec.ActivePolicyVerified, sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("unsupported_bundle_wrong_schema", func(t *testing.T) {
		raw := signedBundleJSON(t, priv, func(m map[string]any) { m["schema_version"] = "policy_bundle_envelope.v1" })
		sec, _ := buildPolicySection(write(raw), trustFP)
		if sec.ActivePolicyVerificationStatus != PolicyVerificationUnsupportedBundle {
			t.Fatalf("status=%q, want unsupported_bundle", sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("unsupported_bundle_self_inconsistent_fp", func(t *testing.T) {
		raw := signedBundleJSON(t, priv, func(m map[string]any) {
			m["signature"].(map[string]any)["public_key_fingerprint"] = otherFP
		})
		sec, _ := buildPolicySection(write(raw), trustFP)
		if sec.ActivePolicyVerificationStatus != PolicyVerificationUnsupportedBundle {
			t.Fatalf("status=%q, want unsupported_bundle (embedded key fp mismatch)", sec.ActivePolicyVerificationStatus)
		}
	})

	t.Run("bundle_unreadable", func(t *testing.T) {
		sec, _ := buildPolicySection(filepath.Join(t.TempDir(), "missing.json"), trustFP)
		if sec.ActivePolicyVerificationStatus != PolicyVerificationBundleUnreadable {
			t.Fatalf("status=%q, want bundle_unreadable", sec.ActivePolicyVerificationStatus)
		}
	})
}

// TestVerifyPolicyBundle_AcceptsVendoredFixture is the contract guard:
// a real policy_bundle.v1 produced by the upstream signer (vendored
// verbatim into testdata) must verify under this node's independently
// implemented signing-payload reconstruction. If the two ever drift,
// this fails — the right failure mode.
func TestVerifyPolicyBundle_AcceptsVendoredFixture(t *testing.T) {
	var bundle rawPolicyBundle
	if err := json.Unmarshal(vendoredPolicyBundleV1, &bundle); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	// Trust exactly the key the fixture was signed with.
	verified, status := verifyPolicyBundle(bundle, bundle.Signature.PublicKeyFingerprint)
	if !verified || status != PolicyVerificationVerified {
		t.Fatalf("vendored policy_bundle.v1 fixture did not verify: verified=%v status=%q "+
			"(signing-payload contract drift?)", verified, status)
	}
}
