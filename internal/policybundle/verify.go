package policybundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// RejectCode is the stable machine reason a bundle failed apply
// verification. Callers branch on it via errors.As to a *RejectError.
type RejectCode string

const (
	RejectDecode             RejectCode = "policy_decode"
	RejectSchemaInvalid      RejectCode = "policy_schema_invalid"
	RejectHashMismatch       RejectCode = "policy_hash_mismatch"
	RejectSigningKeyMismatch RejectCode = "policy_signing_key_mismatch"
	RejectSignatureInvalid   RejectCode = "policy_signature_invalid"
	RejectUnsupportedBundle  RejectCode = "policy_unsupported_bundle"
)

// RejectError is a structured bundle-verification failure carrying the
// stable RejectCode plus an operator-facing message.
type RejectError struct {
	Code RejectCode
	Msg  string
}

func (e *RejectError) Error() string { return string(e.Code) + ": " + e.Msg }

func reject(code RejectCode, format string, args ...any) error {
	return &RejectError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ErrTrustFingerprintRequired is a usage error, not a bundle reject:
// apply verification is meaningless without a trust anchor to compare the
// signing key against. A bundle is never trusted for apply just because it
// is present on disk.
var ErrTrustFingerprintRequired = errors.New("policybundle: a trust fingerprint is required to verify a bundle for apply")

// VerifiedBundle is the typed result of a successful VerifyBundle. The
// caller gets the decoded bundle, the recomputed canonical body bytes, the
// recomputed policy hash, the matched key fingerprint, and the
// UTC-normalized signed_at.
type VerifiedBundle struct {
	Bundle           *PolicyBundle
	CanonicalBody    []byte
	PolicyHash       string
	TrustFingerprint string
	SignedAtUTC      string
}

// VerifyBundle decodes and verifies a signed policy_bundle.v1 strongly
// enough to apply it. It is the contract authority on the Community side:
// it re-runs every cryptographic check rather than trusting any field the
// artifact declares about itself.
//
// Checks fire in a fixed order so the first failure is the cheapest,
// most-informative one:
//
//  1. strict JSON decode + EOF (rejects unknown fields and trailing tokens)
//  2. schema_version / bundle_version / canonicalization / signature.alg
//  3. body re-canonicalization + policy hash recompute (catches any
//     tampering of the signed body — the check reporting verification omits)
//  4. signature public key shape (base64 + Ed25519 length)
//  5. signature self-consistency (sha256(public_key) == claimed fingerprint)
//  6. trust fingerprint match (the operator's apply trust decision)
//  7. signed_at RFC3339 parse + UTC normalize
//  8. Ed25519 verify over the canonical signing payload, using the
//     normalized signed_at and the bound key_id + fingerprint
//
// Steps 3 (hash recompute) and 6 (trust match) are what make this stricter
// than snapshot-time reporting verification.
func VerifyBundle(raw []byte, trustFingerprint string) (*VerifiedBundle, error) {
	if trustFingerprint == "" {
		return nil, ErrTrustFingerprintRequired
	}

	// (1) strict decode + EOF.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b PolicyBundle
	if err := dec.Decode(&b); err != nil {
		return nil, reject(RejectDecode, "decode: %s", err)
	}
	var trailing json.RawMessage
	switch err := dec.Decode(&trailing); {
	case errors.Is(err, io.EOF):
		// clean termination — the only acceptable path
	case err == nil:
		return nil, reject(RejectDecode, "trailing JSON content after the bundle")
	default:
		return nil, reject(RejectDecode, "trailing content after the bundle: %s", err)
	}

	// (2) schema constant tags.
	switch {
	case b.SchemaVersion != SchemaVersion:
		return nil, reject(RejectSchemaInvalid, "schema_version=%q, want %q", b.SchemaVersion, SchemaVersion)
	case b.BundleVersion != BundleVersion:
		return nil, reject(RejectSchemaInvalid, "bundle_version=%d, want %d", b.BundleVersion, BundleVersion)
	case b.Canonicalization != Canonicalization:
		return nil, reject(RejectSchemaInvalid, "canonicalization=%q, want %q", b.Canonicalization, Canonicalization)
	case b.Signature.Alg != SignatureAlg:
		return nil, reject(RejectSchemaInvalid, "signature.alg=%q, want %q", b.Signature.Alg, SignatureAlg)
	}

	// (3) re-canonicalize the body and recompute the hash. A tampered
	// body keeps a well-formed signature block but no longer matches the
	// bytes that signature commits to.
	computed, canonical, err := policyHashHex(b.Policy)
	if err != nil {
		return nil, reject(RejectSchemaInvalid, "canonicalize body: %s", err)
	}
	if computed != b.PolicyHash {
		return nil, reject(RejectHashMismatch, "claimed=%s computed=%s", b.PolicyHash, computed)
	}

	// (4) public key shape.
	pub, err := base64.StdEncoding.DecodeString(b.Signature.PublicKey)
	if err != nil {
		return nil, reject(RejectUnsupportedBundle, "signature.public_key base64 decode: %s", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, reject(RejectUnsupportedBundle, "signature.public_key length=%d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// (5) self-consistency: the embedded key must hash to the fingerprint
	// the bundle claims for it. A mismatch is an internally inconsistent
	// artifact, a distinct failure class from a wrong trust anchor.
	derivedFP := publicKeyFingerprint(ed25519.PublicKey(pub))
	if derivedFP != b.Signature.PublicKeyFingerprint {
		return nil, reject(RejectUnsupportedBundle,
			"signature.public_key_fingerprint claimed=%s computed=%s", b.Signature.PublicKeyFingerprint, derivedFP)
	}

	// (6) trust fingerprint match — the operator's apply trust decision.
	if derivedFP != trustFingerprint {
		return nil, reject(RejectSigningKeyMismatch,
			"bundle signing key %s does not match trust fingerprint %s", derivedFP, trustFingerprint)
	}

	// (7) signed_at parse + UTC normalize. The payload is reconstructed
	// with the UTC form, so a bundle signed in a non-UTC offset still
	// verifies; an unparseable signed_at cannot form a payload at all.
	signedAt, err := time.Parse(time.RFC3339, b.Signature.SignedAt)
	if err != nil {
		return nil, reject(RejectSignatureInvalid, "signature.signed_at not RFC3339: %s", err)
	}
	signedAtUTC := signedAt.UTC().Format(time.RFC3339)

	// (8) signature value + Ed25519 verify over the canonical payload.
	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, reject(RejectSignatureInvalid, "signature.value is not a valid Ed25519 signature")
	}
	payload := policyBundleSigningPayload(
		b.Policy.PolicyID, b.Policy.PolicyVersion, b.PolicyHash,
		signedAtUTC, b.Signature.KeyID, b.Signature.PublicKeyFingerprint)
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sigBytes) {
		return nil, reject(RejectSignatureInvalid, "signature does not verify over the policy_bundle.v1 signing payload")
	}

	return &VerifiedBundle{
		Bundle:           &b,
		CanonicalBody:    canonical,
		PolicyHash:       computed,
		TrustFingerprint: derivedFP,
		SignedAtUTC:      signedAtUTC,
	}, nil
}
