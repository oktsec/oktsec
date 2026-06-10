package policybundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// pullTestKey returns a deterministic Ed25519 key + its fingerprint for index
// signing tests.
func pullTestKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := sha256.Sum256([]byte("oktsec/pull-index-test-key/v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	fp := publicKeyFingerprint(key.Public().(ed25519.PublicKey))
	return key, fp
}

// signIndexForTest builds a valid index.json.sig for the given index bytes,
// mirroring exactly what a store publisher must produce.
func signIndexForTest(t *testing.T, key ed25519.PrivateKey, indexBytes []byte, signedAt, fp string) []byte {
	t.Helper()
	sum := sha256.Sum256(indexBytes)
	payload := PullIndexSigningPayload(signedAt, hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(key, payload)
	out, err := json.Marshal(PullIndexSig{
		SchemaVersion:        PullIndexSigSchemaVersion,
		Alg:                  "Ed25519",
		PublicKey:            base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		PublicKeyFingerprint: fp,
		SignedAt:             signedAt,
		Value:                base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}
	return out
}

func sampleIndexBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(PullIndex{
		SchemaVersion: PullIndexSchemaVersion,
		GeneratedAt:   "2026-06-01T12:00:00Z",
		Entries: []PullIndexEntry{
			{TargetScope: "fleet", BundleFile: "bundles/aaaa.json", PolicyHash: "sha256:aaaa", Sequence: 5},
			{TargetScope: "node", TargetNodeID: "node_x", BundleFile: "bundles/bbbb.json", PolicyHash: "sha256:bbbb", Sequence: 3},
		},
	})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	return raw
}

func TestVerifyPullIndexSig_HappyPath(t *testing.T) {
	key, fp := pullTestKey(t)
	idx := sampleIndexBytes(t)
	sig := signIndexForTest(t, key, idx, "2026-06-01T12:00:00Z", fp)
	if err := VerifyPullIndexSig(idx, sig, fp); err != nil {
		t.Fatalf("valid index signature must verify: %v", err)
	}
}

func TestVerifyPullIndexSig_TamperedIndexFails(t *testing.T) {
	key, fp := pullTestKey(t)
	idx := sampleIndexBytes(t)
	sig := signIndexForTest(t, key, idx, "2026-06-01T12:00:00Z", fp)
	// Flip one byte of the index after signing.
	tampered := append([]byte(nil), idx...)
	tampered[len(tampered)/2] ^= 0x01
	err := VerifyPullIndexSig(tampered, sig, fp)
	if code, ok := AsRejectError(err); !ok || code != RejectPullIndexSigInvalid {
		t.Fatalf("tampered index must fail with %q, got %v", RejectPullIndexSigInvalid, err)
	}
}

func TestVerifyPullIndexSig_WrongTrustFingerprint(t *testing.T) {
	key, fp := pullTestKey(t)
	idx := sampleIndexBytes(t)
	sig := signIndexForTest(t, key, idx, "2026-06-01T12:00:00Z", fp)
	err := VerifyPullIndexSig(idx, sig, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if code, ok := AsRejectError(err); !ok || code != RejectPullIndexKeyMismatch {
		t.Fatalf("wrong trust fingerprint must fail with %q, got %v", RejectPullIndexKeyMismatch, err)
	}
}

func TestVerifyPullIndexSig_KeySelfInconsistent(t *testing.T) {
	key, fp := pullTestKey(t)
	idx := sampleIndexBytes(t)
	// Claim a fingerprint that does not match the embedded key.
	sig := signIndexForTest(t, key, idx, "2026-06-01T12:00:00Z",
		"sha256:1111111111111111111111111111111111111111111111111111111111111111")
	// The pinned fingerprint matches the bogus claim, but self-consistency
	// (sha256(public_key) == claimed) must still fail first.
	err := VerifyPullIndexSig(idx, sig, "sha256:1111111111111111111111111111111111111111111111111111111111111111")
	if code, ok := AsRejectError(err); !ok || code != RejectPullIndexKeyMismatch {
		t.Fatalf("self-inconsistent key must fail with %q, got %v", RejectPullIndexKeyMismatch, err)
	}
	_ = fp
}

func TestParsePullIndex_StrictAndSchema(t *testing.T) {
	if _, err := ParsePullIndex([]byte(`{"schema_version":"wrong","entries":[]}`)); err == nil {
		t.Fatal("wrong schema_version must be rejected")
	}
	if _, err := ParsePullIndex([]byte(`{"schema_version":"oktsec_pull_index.v1","bogus":1,"entries":[]}`)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
	// Trailing content after the object must be rejected (strict EOF), so a
	// signature over only the leading object cannot cover a smuggled tail.
	tail := append(append([]byte(nil), sampleIndexBytes(t)...), []byte(`{"x":1}`)...)
	if _, err := ParsePullIndex(tail); err == nil {
		t.Fatal("trailing content after the index object must be rejected")
	}
	idx, err := ParsePullIndex(sampleIndexBytes(t))
	if err != nil {
		t.Fatalf("valid index must parse: %v", err)
	}
	if len(idx.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(idx.Entries))
	}
}

func TestVerifyPullIndexSig_TrailingContentRejected(t *testing.T) {
	key, fp := pullTestKey(t)
	idx := sampleIndexBytes(t)
	sig := signIndexForTest(t, key, idx, "2026-06-01T12:00:00Z", fp)
	tail := append(append([]byte(nil), sig...), []byte(`garbage`)...)
	if err := VerifyPullIndexSig(idx, tail, fp); err == nil {
		t.Fatal("trailing content after the signature object must be rejected")
	}
}

func TestSelectPullEntry(t *testing.T) {
	idx, err := ParsePullIndex(sampleIndexBytes(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Node-scoped entry wins for its node.
	e, ok := SelectPullEntry(idx, "node_x")
	if !ok || e.TargetScope != "node" || e.TargetNodeID != "node_x" {
		t.Fatalf("node_x must select its node entry, got %+v ok=%v", e, ok)
	}
	// A different node falls back to the fleet entry.
	e, ok = SelectPullEntry(idx, "node_other")
	if !ok || e.TargetScope != "fleet" {
		t.Fatalf("node_other must fall back to fleet, got %+v ok=%v", e, ok)
	}
	// No fleet entry + no matching node => nothing to pull.
	fleetless := &PullIndex{SchemaVersion: PullIndexSchemaVersion, Entries: []PullIndexEntry{
		{TargetScope: "node", TargetNodeID: "node_x", BundleFile: "b"},
	}}
	if _, ok := SelectPullEntry(fleetless, "node_other"); ok {
		t.Fatal("node_other with no fleet entry must select nothing")
	}
}

func TestVerifyPullIndexSig_MalformedSigRejected(t *testing.T) {
	_, fp := pullTestKey(t)
	idx := sampleIndexBytes(t)
	if err := VerifyPullIndexSig(idx, []byte(`{not json`), fp); err == nil {
		t.Fatal("malformed sig must be rejected")
	}
	if !strings.HasPrefix(string(sampleIndexBytes(t)), "{") {
		t.Fatal("sanity: index is JSON object")
	}
}
