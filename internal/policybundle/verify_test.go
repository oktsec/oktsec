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

// wantRejectMsg is wantReject with a case label for table-driven tests.
func wantRejectMsg(t *testing.T, err error, code RejectCode, label string) {
	t.Helper()
	var re *RejectError
	if !errors.As(err, &re) {
		t.Fatalf("[%s] error %v is not a *RejectError", label, err)
	}
	if re.Code != code {
		t.Fatalf("[%s] reject code = %q, want %q (%s)", label, re.Code, code, re.Msg)
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

// nonCanonicalTimestamps are byte-different-but-equivalent (or invalid)
// timestamp strings that policy_bundle.v1 must reject. There is exactly one
// canonical wire form (YYYY-MM-DDTHH:MM:SSZ); everything else is a
// schema/canonicalization failure, not a signature failure.
var nonCanonicalTimestamps = []string{
	"2026-05-23T12:00:00.000Z",        // fractional seconds (zeroes)
	"2026-05-23T12:00:00.999Z",        // fractional seconds
	"2026-05-23T12:00:00.0000000001Z", // more than 9 fractional digits
	"2026-05-23T09:00:00-03:00",       // offset form (equivalent instant)
	"2026-05-23t12:00:00Z",            // lowercase separator
	"2026-05-23T12:00:00z",            // lowercase zone
	"2026-05-23T12:00:60Z",            // leap second / invalid time
	"2026-02-30T12:00:00Z",            // invalid calendar date
}

func TestVerify_NonCanonicalCreatedAtRejected(t *testing.T) {
	_, fp := loadFixture(t)
	for _, ts := range nonCanonicalTimestamps {
		raw := remarshal(t, func(b *PolicyBundle) { b.Policy.Metadata.CreatedAt = ts })
		_, err := VerifyBundle(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "created_at "+ts)
	}
}

func TestVerify_NonCanonicalSignedAtRejected(t *testing.T) {
	_, fp := loadFixture(t)
	for _, ts := range nonCanonicalTimestamps {
		raw := remarshal(t, func(b *PolicyBundle) { b.Signature.SignedAt = ts })
		_, err := VerifyBundle(raw, fp)
		wantRejectMsg(t, err, RejectSchemaInvalid, "signed_at "+ts)
	}
}

// A canonical-but-different created_at second passes the form check, so the
// body hash recompute must catch it (the hash covers exact wire bytes, with
// no normalization that could fold two values together).
func TestVerify_CanonicalCreatedAtChangeIsHashMismatch(t *testing.T) {
	_, fp := loadFixture(t)
	raw := remarshal(t, func(b *PolicyBundle) { b.Policy.Metadata.CreatedAt = "2030-01-01T00:00:00Z" })
	_, err := VerifyBundle(raw, fp)
	wantReject(t, err, RejectHashMismatch)
}

// A canonical-but-different signed_at second passes the form check and does
// not affect the body hash, so the signature (which binds the exact wire
// signed_at) must fail.
func TestVerify_CanonicalSignedAtChangeBreaksSignature(t *testing.T) {
	_, fp := loadFixture(t)
	raw := remarshal(t, func(b *PolicyBundle) { b.Signature.SignedAt = "2030-01-01T00:00:00Z" })
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
