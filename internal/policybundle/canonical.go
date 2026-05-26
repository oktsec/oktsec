package policybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// canonicalPolicyBodyBytes returns the exact byte layout that policy_hash
// and the Ed25519 signature cover: a typed-struct JSON projection of the
// body, HTML escaping off, no trailing newline. Encoding the typed struct
// (never a map[string]any) fixes field order; map keys serialize
// alphabetically under encoding/json, so Rules.Overrides is deterministic.
//
// Timestamps are NOT normalized here. The verifier hashes the exact wire
// strings (per the policy_bundle.v1 canonicalization amendment): a verifier
// must not make tampered bytes disappear by parsing and reformatting them.
// The signer is responsible for embedding canonical timestamp strings;
// validateCanonicalPolicyTimestamp enforces the single accepted form before
// the hash is recomputed.
func canonicalPolicyBodyBytes(body PolicyBody) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, fmt.Errorf("encode canonical body: %w", err)
	}
	// Encode appends a trailing newline; strip it so the hashed bytes are
	// exactly the marshaled JSON.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// canonicalTimestamp is the single accepted policy_bundle.v1 timestamp wire
// form: UTC, seconds precision, uppercase T and Z, exactly 20 bytes. No
// fractional seconds, no offsets, no lowercase variants.
var canonicalTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// validateCanonicalPolicyTimestamp rejects any timestamp string that is not
// the single canonical wire form. It first checks the exact byte shape
// (which alone rejects fractional seconds, offsets, lowercase t/z, and wrong
// length), then parses to reject impossible calendar values and leap-second
// ":60". It returns no replacement string: the caller hashes and signs the
// original wire bytes, so there is no "same instant" equivalence class —
// a byte-different timestamp is a different artifact.
func validateCanonicalPolicyTimestamp(s string) error {
	if !canonicalTimestamp.MatchString(s) {
		return fmt.Errorf("not canonical YYYY-MM-DDTHH:MM:SSZ form: %q", s)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", s); err != nil {
		return fmt.Errorf("not a valid UTC timestamp: %q", s)
	}
	return nil
}

// policyHashHex returns the sha256 hex of the canonical body bytes with
// the "sha256:" wire prefix, plus the canonical bytes themselves.
func policyHashHex(body PolicyBody) (string, []byte, error) {
	canon, err := canonicalPolicyBodyBytes(body)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), canon, nil
}

// policyBundleSigningPayload returns the exact bytes the Ed25519 signature
// covers: domain-separated labeled lines, newline-joined, no trailing
// newline. The header and the bundle_version / canonicalization tags make
// the payload schema-specific so two artifacts sharing free-form values
// cannot collide across schemas. key_id and the public key fingerprint are
// part of the payload — bound by the signature — so they cannot be
// rewritten after signing. The signer and this verifier MUST produce
// identical bytes or every signature fails to verify.
func policyBundleSigningPayload(policyID, policyVersion, policyHash, signedAt, keyID, publicKeyFingerprint string) []byte {
	lines := []string{
		"oktsec." + SchemaVersion,
		fmt.Sprintf("bundle_version:%d", BundleVersion),
		"policy_id:" + policyID,
		"policy_version:" + policyVersion,
		"policy_hash:" + policyHash,
		"canonicalization:" + Canonicalization,
		"signed_at:" + signedAt,
		"signature_key_id:" + keyID,
		"signature_public_key_fingerprint:" + publicKeyFingerprint,
	}
	return []byte(strings.Join(lines, "\n"))
}

// publicKeyFingerprint is the policy_bundle.v1 key fingerprint format:
// sha256:<64-hex> over the raw Ed25519 public key bytes.
func publicKeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}
