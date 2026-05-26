package policybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// canonicalPolicyBodyBytes returns the exact byte layout that policy_hash
// and the Ed25519 signature cover: a typed-struct JSON projection of the
// body, HTML escaping off, no trailing newline. Encoding the typed struct
// (never a map[string]any) fixes field order; map keys serialize
// alphabetically under encoding/json, so Rules.Overrides is deterministic.
//
// Metadata.created_at is UTC-normalized: a value that parses as RFC3339 is
// rewritten to its UTC form, so two bundles that wrote the same instant in
// different timezones canonicalize identically. A value that does not parse
// is left as-is.
func canonicalPolicyBodyBytes(body PolicyBody) ([]byte, error) {
	body.Metadata.CreatedAt = normalizeRFC3339OrKeep(body.Metadata.CreatedAt)
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

// normalizeRFC3339OrKeep rewrites a timestamp to UTC if it parses as
// RFC3339, otherwise returns it verbatim.
func normalizeRFC3339OrKeep(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}
