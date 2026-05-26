package policybundle

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// fixtureBytes is a deterministically signed policy_bundle.v1 produced by
// the upstream signer, vendored verbatim. It is embedded (not placed under
// the gitignored testdata/) so it ships with the package and guards the
// canonicalization + signing payload against drift on every CI run.
//
//go:embed policy_bundle_v1_fixture.json
var fixtureBytes []byte

// loadFixture returns the vendored fixture and its self-declared trust
// fingerprint.
func loadFixture(t *testing.T) (raw []byte, trustFP string) {
	t.Helper()
	var b PolicyBundle
	if err := json.Unmarshal(fixtureBytes, &b); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fixtureBytes, b.Signature.PublicKeyFingerprint
}

// remarshal mutates the fixture's typed form and returns valid JSON the
// strict verifier accepts structurally (so a check past decode can fire).
func remarshal(t *testing.T, mutate func(b *PolicyBundle)) []byte {
	t.Helper()
	raw, _ := loadFixture(t)
	var b PolicyBundle
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

func wantReject(t *testing.T, err error, code RejectCode) {
	t.Helper()
	var re *RejectError
	if !errors.As(err, &re) {
		t.Fatalf("error %v is not a *RejectError", err)
	}
	if re.Code != code {
		t.Fatalf("reject code = %q, want %q (%s)", re.Code, code, re.Msg)
	}
}

func TestVerify_FixtureVerifies(t *testing.T) {
	raw, fp := loadFixture(t)
	v, err := VerifyBundle(raw, fp)
	if err != nil {
		t.Fatalf("fixture must verify: %v", err)
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
}

// TestVerify_HashMatchesContract is the anti-drift guard: the Community
// canonicalizer must reproduce, byte-for-byte, the policy hash the signer
// declared. If the canonicalization diverges this fails.
func TestVerify_HashMatchesContract(t *testing.T) {
	raw, _ := loadFixture(t)
	var b PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	computed, _, err := policyHashHex(b.Policy)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if computed != b.PolicyHash {
		t.Fatalf("canonicalizer drift: declared=%s computed=%s", b.PolicyHash, computed)
	}
}

func TestVerify_TamperedBody(t *testing.T) {
	_, fp := loadFixture(t)
	// Change a signed body field; the declared hash + signature stay, so
	// the recomputed hash no longer matches.
	raw := remarshal(t, func(b *PolicyBundle) { b.Policy.Mode = "observe" })
	_, err := VerifyBundle(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

func TestVerify_SignatureMismatch(t *testing.T) {
	_, fp := loadFixture(t)
	raw := remarshal(t, func(b *PolicyBundle) {
		sig, _ := base64.StdEncoding.DecodeString(b.Signature.Value)
		sig[0] ^= 0xff // flip a byte: valid shape, wrong signature
		b.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	})
	_, err := VerifyBundle(raw, fp)
	wantReject(t, err, RejectSignatureInvalid)
}

func TestVerify_WrongTrustFingerprint(t *testing.T) {
	raw, _ := loadFixture(t)
	// A real, self-consistent bundle but the operator's trust anchor is a
	// different key.
	other := publicKeyFingerprint(make(ed25519.PublicKey, ed25519.PublicKeySize))
	_, err := VerifyBundle(raw, other)
	wantReject(t, err, RejectSigningKeyMismatch)
}

func TestVerify_SelfInconsistentKey(t *testing.T) {
	_, fp := loadFixture(t)
	// Claimed fingerprint no longer matches the embedded public key.
	raw := remarshal(t, func(b *PolicyBundle) {
		b.Signature.PublicKeyFingerprint = publicKeyFingerprint(make(ed25519.PublicKey, ed25519.PublicKeySize))
	})
	_, err := VerifyBundle(raw, fp)
	wantReject(t, err, RejectUnsupportedBundle)
}

func TestVerify_SignedAtIsBound(t *testing.T) {
	_, fp := loadFixture(t)
	// Editing signed_at after signing — even adding fractional seconds the
	// RFC3339 reformatter would have dropped — must break verification,
	// because the signature binds the exact signed_at bytes.
	raw := remarshal(t, func(b *PolicyBundle) {
		b.Signature.SignedAt = "2099-01-01T00:00:00.500Z"
	})
	_, err := VerifyBundle(raw, fp)
	wantReject(t, err, RejectSignatureInvalid)
}

func TestVerify_SchemaInvalid(t *testing.T) {
	_, fp := loadFixture(t)
	raw := remarshal(t, func(b *PolicyBundle) { b.SchemaVersion = "policy_bundle.v2" })
	_, err := VerifyBundle(raw, fp)
	wantReject(t, err, RejectSchemaInvalid)
}

func TestVerify_UnknownField(t *testing.T) {
	raw, fp := loadFixture(t)
	// Inject an unknown top-level field; strict decode must refuse it.
	injected := append([]byte(`{"x_unknown_field": 1,`), raw[1:]...)
	_, err := VerifyBundle(injected, fp)
	wantReject(t, err, RejectDecode)
}

func TestVerify_TrailingJSON(t *testing.T) {
	raw, fp := loadFixture(t)
	withTrailing := append(append([]byte{}, raw...), []byte("\n{}\n")...)
	_, err := VerifyBundle(withTrailing, fp)
	wantReject(t, err, RejectDecode)
}

func TestVerify_EmptyTrustIsUsageError(t *testing.T) {
	raw, _ := loadFixture(t)
	_, err := VerifyBundle(raw, "")
	if !errors.Is(err, ErrTrustFingerprintRequired) {
		t.Fatalf("empty trust fingerprint must be a usage error, got %v", err)
	}
	var re *RejectError
	if errors.As(err, &re) {
		t.Fatal("empty trust fingerprint must not be a bundle reject code")
	}
}

// TestSigningPayload_Stable locks the cross-repo byte layout of the
// signing payload. The signer and this verifier must agree exactly.
func TestSigningPayload_Stable(t *testing.T) {
	got := string(policyBundleSigningPayload(
		"voice-ai-prod", "1", "sha256:abc", "2026-01-01T00:00:00Z", "kid", "sha256:fp"))
	want := "oktsec.policy_bundle.v1\n" +
		"bundle_version:1\n" +
		"policy_id:voice-ai-prod\n" +
		"policy_version:1\n" +
		"policy_hash:sha256:abc\n" +
		"canonicalization:oktsec-policy-v1-typed-utc-json\n" +
		"signed_at:2026-01-01T00:00:00Z\n" +
		"signature_key_id:kid\n" +
		"signature_public_key_fingerprint:sha256:fp"
	if got != want {
		t.Fatalf("signing payload layout drift:\n got=%q\nwant=%q", got, want)
	}
}
