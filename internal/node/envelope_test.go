package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// baseSnapshot returns a Snapshot whose identity fields match the
// IdentityStore the test seeds. Tests mutate just the fields they
// need so the diff between cases stays narrow.
func baseSnapshot(id *Identity) Snapshot {
	return Snapshot{
		SchemaVersion: SchemaSnapshot,
		GeneratedAt:   "2026-05-22T00:00:00Z",
		Range: SnapshotRange{
			Since: "2026-05-21T00:00:00Z",
		},
		Node: SnapshotNode{
			NodeID:               id.NodeID,
			IdentityStatus:       "present",
			HostFingerprint:      id.HostFingerprint,
			PublicKeyFingerprint: id.PublicKeyFingerprint,
			GOOS:                 "linux",
			GOARCH:               "amd64",
			Profile:              ProfileLocal,
		},
		Config:    SnapshotConfig{Status: "missing"},
		Inventory: SnapshotInventory{},
	}
}

// seedIdentity returns a fresh IdentityStore + the matching
// Identity record so envelope tests have a working signer.
func seedIdentity(t *testing.T) (IdentityStore, *Identity) {
	t.Helper()
	store := IdentityStore{Dir: filepath.Join(t.TempDir(), "node")}
	id, err := store.Init(ProfileLocal)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return store, id
}

func TestCanonicalSnapshotBytes_StableAcrossWhitespace(t *testing.T) {
	// Two semantically-identical snapshots must canonicalize to
	// the same bytes regardless of how the test built them. The
	// guarantee is critical because it is the signer/verifier
	// contract: any whitespace divergence here would silently
	// break Enterprise's signature check.
	_, id := seedIdentity(t)
	a := baseSnapshot(id)
	b := baseSnapshot(id)
	canonA, err := CanonicalSnapshotBytes(a)
	if err != nil {
		t.Fatalf("canon a: %v", err)
	}
	canonB, err := CanonicalSnapshotBytes(b)
	if err != nil {
		t.Fatalf("canon b: %v", err)
	}
	if string(canonA) != string(canonB) {
		t.Fatalf("canonical bytes diverge for equivalent snapshots:\n  a=%q\n  b=%q",
			canonA, canonB)
	}
	// And no trailing newline survived encoder.Encode.
	if strings.HasSuffix(string(canonA), "\n") {
		t.Fatalf("canonical bytes must not end with newline: %q", canonA)
	}
}

func TestCanonicalSnapshotBytes_NormalizesZoneOffset(t *testing.T) {
	// generated_at expressed in two equivalent zone forms must
	// produce identical canonical bytes. The fixture in
	// Enterprise's vendored corpus relies on this so a
	// snapshot signed under -03:00 verifies after the operator
	// moves the file across zones.
	_, id := seedIdentity(t)
	utc := baseSnapshot(id)
	offset := baseSnapshot(id)
	offset.GeneratedAt = "2026-05-21T21:00:00-03:00"     // same instant as utc.GeneratedAt
	offset.Range.Since = "2026-05-20T21:00:00-03:00"     // same instant as utc.Range.Since
	hashUTC, _, err := SnapshotSHA256(utc)
	if err != nil {
		t.Fatalf("hash utc: %v", err)
	}
	hashOffset, _, err := SnapshotSHA256(offset)
	if err != nil {
		t.Fatalf("hash offset: %v", err)
	}
	if hashUTC != hashOffset {
		t.Fatalf("zone-shifted equivalent timestamps must produce identical hash: utc=%s offset=%s",
			hashUTC, hashOffset)
	}
}

func TestCanonicalSnapshotBytes_DoesNotMutateCaller(t *testing.T) {
	_, id := seedIdentity(t)
	s := baseSnapshot(id)
	s.GeneratedAt = "2026-05-21T21:00:00-03:00"
	before := s.GeneratedAt
	if _, err := CanonicalSnapshotBytes(s); err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if s.GeneratedAt != before {
		t.Fatalf("CanonicalSnapshotBytes must not mutate caller's Snapshot; got %q want %q",
			s.GeneratedAt, before)
	}
}

func TestSnapshotEnvelopeSigningPayload_ExactBytes(t *testing.T) {
	got := SnapshotEnvelopeSigningPayload(
		"node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"deadbeef",
		"2026-05-22T00:00:00Z",
	)
	want := strings.Join([]string{
		"oktsec.node_snapshot_envelope.v1",
		"node_id:node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"snapshot_sha256:deadbeef",
		"snapshot_schema_version:node_snapshot.v1",
		"canonicalization:node_snapshot.v1.canonical_json.utc_minified",
		"signed_at:2026-05-22T00:00:00Z",
	}, "\n")
	if string(got) != want {
		t.Fatalf("payload bytes diverge:\n  got:  %q\n  want: %q", got, want)
	}
	if strings.HasSuffix(string(got), "\n") {
		t.Fatalf("payload must not end with newline")
	}
}

func TestSealSnapshotEnvelope_HappyPath(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	env, err := SealSnapshotEnvelope(store, snap, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env.SchemaVersion != SchemaSnapshotEnvelope ||
		env.EnvelopeVersion != EnvelopeVersion {
		t.Fatalf("envelope versions wrong: %+v", env)
	}
	if env.NodeID != id.NodeID || env.Signature.KeyID != id.NodeID {
		t.Fatalf("envelope/sig node mismatch: %+v", env)
	}
	if env.Canonicalization != CanonicalizationTag {
		t.Fatalf("canonicalization tag wrong: %q", env.Canonicalization)
	}
	hash, _, err := SnapshotSHA256(snap)
	if err != nil {
		t.Fatalf("recompute hash: %v", err)
	}
	if env.SnapshotSHA256 != hash {
		t.Fatalf("envelope hash diverges from local SnapshotSHA256: %s vs %s",
			env.SnapshotSHA256, hash)
	}
	// Verify the signature with the public key the envelope
	// carries — this mirrors what Enterprise will do.
	pubBytes, err := base64.StdEncoding.DecodeString(env.Signature.PublicKey)
	if err != nil {
		t.Fatalf("decode public_key: %v", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("public_key length %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	payload := SnapshotEnvelopeSigningPayload(env.NodeID, env.SnapshotSHA256, env.Signature.SignedAt)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes) {
		t.Fatalf("ed25519.Verify failed against envelope's own public key")
	}
}

func TestSealSnapshotEnvelope_RefusesNodeIDMismatch(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Node.NodeID = "node_" + strings.Repeat("1", 36)
	_, err := SealSnapshotEnvelope(store, snap, time.Now())
	if err == nil {
		t.Fatalf("snapshot with foreign node_id must refuse signing")
	}
	if !strings.Contains(err.Error(), "node_id") {
		t.Fatalf("error must mention node_id, got %v", err)
	}
}

func TestSealSnapshotEnvelope_RefusesPubKeyFingerprintMismatch(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Node.PublicKeyFingerprint = "sha256:" + strings.Repeat("e", 64)
	_, err := SealSnapshotEnvelope(store, snap, time.Now())
	if err == nil {
		t.Fatalf("snapshot with foreign pubkey fingerprint must refuse signing")
	}
}

func TestSealSnapshotEnvelope_RefusesHostMismatchWhenBothPresent(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Node.HostFingerprint = "sha256:" + strings.Repeat("c", 64)
	_, err := SealSnapshotEnvelope(store, snap, time.Now())
	if err == nil {
		t.Fatalf("snapshot host_fp mismatch must refuse signing")
	}
}

func TestSealSnapshotEnvelope_AcceptsHostMissingOnEitherSide(t *testing.T) {
	// When the snapshot omits host_fingerprint (older Community
	// build, or an explicit operator scrub) the check is
	// skipped. The pubkey/node_id checks still gate the call.
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Node.HostFingerprint = ""
	if _, err := SealSnapshotEnvelope(store, snap, time.Now()); err != nil {
		t.Fatalf("missing snapshot host_fp must not refuse signing: %v", err)
	}
}

func TestSealSnapshotEnvelope_RefusesUnpresentIdentityStatus(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Node.IdentityStatus = "missing"
	_, err := SealSnapshotEnvelope(store, snap, time.Now())
	if err == nil {
		t.Fatalf("snapshot with identity_status != present must refuse signing")
	}
}

func TestSealSnapshotEnvelope_NormalizesSignedAtToUTC(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	// Use a non-UTC location to force a normalization step.
	loc, err := time.LoadLocation("America/Argentina/Buenos_Aires")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	ts := time.Date(2026, 5, 21, 21, 0, 0, 0, loc) // same instant as 2026-05-22T00:00:00Z
	env, err := SealSnapshotEnvelope(store, snap, ts)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env.Signature.SignedAt != "2026-05-22T00:00:00Z" {
		t.Fatalf("signed_at not UTC-normalized: %q", env.Signature.SignedAt)
	}
}

func TestSealSnapshotEnvelope_JSONShape(t *testing.T) {
	// The envelope must marshal to a JSON object whose top-level
	// keys match the spec; Enterprise's vendored JSON Schema will
	// be derived from this shape. Spot-check the keys here so a
	// future struct reorder shows up as a real test failure
	// rather than a downstream verifier mystery.
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	env, err := SealSnapshotEnvelope(store, snap, time.Now().UTC())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	buf, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf, &raw); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	for _, key := range []string{
		"schema_version", "envelope_version", "node_id",
		"snapshot_schema_version", "snapshot_sha256",
		"canonicalization", "signature", "snapshot",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("envelope JSON missing key %q", key)
		}
	}
	var sig map[string]json.RawMessage
	if err := json.Unmarshal(raw["signature"], &sig); err != nil {
		t.Fatalf("re-parse signature: %v", err)
	}
	for _, key := range []string{
		"alg", "key_id", "public_key", "public_key_fingerprint",
		"signed_at", "value",
	} {
		if _, ok := sig[key]; !ok {
			t.Errorf("signature JSON missing key %q", key)
		}
	}
}

func TestSealSnapshotEnvelope_RefusesWhenIdentityMissing(t *testing.T) {
	// Pointing the store at an empty directory simulates an
	// uninitialized node — the signing path must refuse rather
	// than emit an envelope signed with whatever key it could
	// scrape together.
	store := IdentityStore{Dir: filepath.Join(t.TempDir(), "empty-node")}
	snap := Snapshot{SchemaVersion: SchemaSnapshot, Node: SnapshotNode{
		NodeID: "node_" + strings.Repeat("a", 36),
		IdentityStatus: "present",
	}}
	_, err := SealSnapshotEnvelope(store, snap, time.Now())
	if err == nil {
		t.Fatalf("missing identity must refuse signing")
	}
}
