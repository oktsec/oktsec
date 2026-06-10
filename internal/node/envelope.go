package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Stable envelope schema version. Bumping is a contract break and
// must come with a coordinated consumer-side release; this constant
// is the single source of truth on the Community side and the value
// downstream verifiers vendor into their JSON Schema fixtures.
const SchemaSnapshotEnvelope = "node_snapshot_envelope.v1"

// EnvelopeVersion is the integer envelope-shape version. Distinct
// from SchemaSnapshotEnvelope so a future field-only addition can
// bump the integer without rotating the schema name; current
// verifiers should still accept it under the same
// schema string, refusing fields they do not understand.
const EnvelopeVersion = 1

// CanonicalizationTag identifies the exact canonicalization
// algorithm used to compute the snapshot hash that goes into the
// envelope. Verifiers must check this exact tag so an
// untagged or differently-tagged envelope is rejected outright.
const CanonicalizationTag = "node_snapshot.v1.canonical_json.utc_minified"

// SnapshotSignature is the cryptographic-evidence half of the
// envelope. The public key is carried in raw base64 form because
// node_identity.v1 only exposes the fingerprint; without the raw
// bytes a verifier cannot check the Ed25519 signature.
type SnapshotSignature struct {
	Alg                  string `json:"alg"`
	KeyID                string `json:"key_id"`
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	SignedAt             string `json:"signed_at"`
	Value                string `json:"value"`
}

// SnapshotEnvelope is the signed wrapper around a redacted
// node_snapshot.v1 artifact. Field order in the struct controls JSON
// marshal order, which the canonical-bytes contract relies on; do not
// reorder without bumping EnvelopeVersion.
//
// Embedded Snapshot is the SAME shape `oktsec node snapshot --json`
// emits; the envelope adds no new snapshot data and never carries
// raw prompts, tool I/O, host names or filesystem paths beyond what
// node_snapshot.v1 already redacts.
type SnapshotEnvelope struct {
	SchemaVersion         string            `json:"schema_version"`
	EnvelopeVersion       int               `json:"envelope_version"`
	NodeID                string            `json:"node_id"`
	SnapshotSchemaVersion string            `json:"snapshot_schema_version"`
	SnapshotSHA256        string            `json:"snapshot_sha256"`
	Canonicalization      string            `json:"canonicalization"`
	Signature             SnapshotSignature `json:"signature"`
	Snapshot              Snapshot          `json:"snapshot"`
}

// CanonicalSnapshotBytes returns the bytes a verifier must reproduce
// to verify the signature. The contract:
//
//  1. RFC3339 timestamps that the snapshot uses for time bounds
//     (generated_at, range.since, range.until) are parsed and
//     re-emitted in UTC. A zone-shifted but identical-instant
//     value normalizes to the same string.
//  2. The typed Snapshot struct is marshalled with encoding/json's
//     SetEscapeHTML(false) so '<', '>', '&' are not rewritten into
//     Unicode escapes by either side.
//  3. The trailing newline json.Encoder adds is stripped — the
//     canonical bytes are exactly the JSON object body.
//
// The function does NOT mutate the caller's Snapshot; a shallow
// copy is enough because the only field types touched are strings.
//
// Returning the canonical bytes (not just the hash) lets callers
// avoid the second walk through CanonicalSnapshotBytes when they
// later embed the snapshot back into an envelope — SnapshotSHA256
// is the helper for the common path.
func CanonicalSnapshotBytes(s Snapshot) ([]byte, error) {
	s.GeneratedAt = normalizeRFC3339OrKeep(s.GeneratedAt)
	s.Range.Since = normalizeRFC3339OrKeep(s.Range.Since)
	if s.Range.Until != "" {
		s.Range.Until = normalizeRFC3339OrKeep(s.Range.Until)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, fmt.Errorf("canonical snapshot encode: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SnapshotSHA256 returns the lowercase-hex SHA-256 of the canonical
// snapshot bytes, paired with those bytes. The hash has NO sha256:
// prefix because consumer snapshot IDs already use raw hex; the
// fingerprint prefix is reserved for identity-shaped values.
func SnapshotSHA256(s Snapshot) (string, []byte, error) {
	canon, err := CanonicalSnapshotBytes(s)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), canon, nil
}

// SnapshotEnvelopeSigningPayload returns the exact byte sequence
// that gets signed. The format is domain-separated lines joined by
// "\n" with no trailing newline. The helper owns the byte layout so
// signer and verifier cannot drift: callers MUST NOT hand-assemble
// the payload from these arguments.
//
// Lines (in order):
//
//	oktsec.node_snapshot_envelope.v1
//	node_id:<node_id>
//	snapshot_sha256:<snapshot_sha256>
//	snapshot_schema_version:node_snapshot.v1
//	canonicalization:<CanonicalizationTag>
//	signed_at:<signed_at>
//
// Any change here is a contract break and requires a v2 envelope.
func SnapshotEnvelopeSigningPayload(nodeID, snapshotSHA256, signedAt string) []byte {
	lines := []string{
		"oktsec." + SchemaSnapshotEnvelope,
		"node_id:" + nodeID,
		"snapshot_sha256:" + snapshotSHA256,
		"snapshot_schema_version:" + SchemaSnapshot,
		"canonicalization:" + CanonicalizationTag,
		"signed_at:" + signedAt,
	}
	return []byte(strings.Join(lines, "\n"))
}

// SealSnapshotEnvelope binds a redacted Snapshot to a node identity
// by signing it with the supplied IdentityStore. It does NOT load
// the snapshot from disk or validate the snapshot beyond identity-
// agreement checks — the caller (oktsec node sign-snapshot) is
// responsible for schema validation, symlink refusal, and size
// limits before calling here.
//
// Identity agreement checks run BEFORE signing so a hand-edited
// snapshot whose node_id or fingerprint do not match the local
// identity is rejected without producing a misleading signature.
// Order 2 of the trust model relies on this: an envelope is only
// trustworthy because the signing node also vouched for the
// metadata it covers.
//
// signedAt is normalized to UTC RFC3339 before signing AND before
// being written into the envelope, so a future verifier sees the
// same string the signer hashed.
func SealSnapshotEnvelope(store IdentityStore, snap Snapshot, signedAt time.Time) (*SnapshotEnvelope, error) {
	id, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("sign-snapshot: load identity: %w", err)
	}
	if snap.Node.IdentityStatus != "present" {
		return nil, fmt.Errorf("sign-snapshot: snapshot identity_status is %q; need 'present'", snap.Node.IdentityStatus)
	}
	if snap.Node.NodeID != id.NodeID {
		return nil, fmt.Errorf("sign-snapshot: snapshot node_id %q does not match local identity %q",
			snap.Node.NodeID, id.NodeID)
	}
	if snap.Node.PublicKeyFingerprint != id.PublicKeyFingerprint {
		return nil, fmt.Errorf("sign-snapshot: snapshot public_key_fingerprint does not match local identity")
	}
	if snap.Node.HostFingerprint != "" && id.HostFingerprint != "" &&
		snap.Node.HostFingerprint != id.HostFingerprint {
		return nil, fmt.Errorf("sign-snapshot: snapshot host_fingerprint does not match local identity (snapshot was taken on a different host)")
	}
	pub, err := store.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("sign-snapshot: read public key: %w", err)
	}
	hash, _, err := SnapshotSHA256(snap)
	if err != nil {
		return nil, err
	}
	ts := signedAt.UTC().Format(time.RFC3339)
	payload := SnapshotEnvelopeSigningPayload(id.NodeID, hash, ts)
	sig, err := store.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("sign-snapshot: sign payload: %w", err)
	}
	env := &SnapshotEnvelope{
		SchemaVersion:         SchemaSnapshotEnvelope,
		EnvelopeVersion:       EnvelopeVersion,
		NodeID:                id.NodeID,
		SnapshotSchemaVersion: SchemaSnapshot,
		SnapshotSHA256:        hash,
		Canonicalization:      CanonicalizationTag,
		Signature: SnapshotSignature{
			Alg:                  "Ed25519",
			KeyID:                id.NodeID,
			PublicKey:            base64.StdEncoding.EncodeToString(pub),
			PublicKeyFingerprint: id.PublicKeyFingerprint,
			SignedAt:             ts,
			Value:                sig.Base64,
		},
		Snapshot: snap,
	}
	// Sanity check the produced signature with the public key
	// we just emitted; a mismatch here would mean the
	// IdentityStore's key files are out of sync with each other
	// (private key signs something the public key cannot
	// verify) — refuse to emit such an envelope.
	if err := verifyEnvelopeSelf(env, pub); err != nil {
		return nil, fmt.Errorf("sign-snapshot: post-sign self-check failed: %w", err)
	}
	return env, nil
}

// verifyEnvelopeSelf runs the same Ed25519 verification a
// downstream verifier would run, against the IdentityStore's
// current public key. It catches an entire class of subtle
// breakage (mismatched key files, accidental key rotation
// mid-process) without depending on any external verifier.
func verifyEnvelopeSelf(env *SnapshotEnvelope, pub ed25519.PublicKey) error {
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("signature length %d, want %d", len(sigBytes), ed25519.SignatureSize)
	}
	payload := SnapshotEnvelopeSigningPayload(env.NodeID, env.SnapshotSHA256, env.Signature.SignedAt)
	if !ed25519.Verify(pub, payload, sigBytes) {
		return fmt.Errorf("ed25519.Verify returned false")
	}
	return nil
}

// normalizeRFC3339OrKeep returns the UTC RFC3339 form of s when s
// parses, and the original string otherwise. The canonicalizer
// uses this so a missing or non-RFC3339 timestamp does not crash
// the signing path — schema validation upstream is the gate that
// catches malformed timestamps before we reach here.
func normalizeRFC3339OrKeep(s string) string {
	if s == "" {
		return s
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}
