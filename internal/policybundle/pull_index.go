package policybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// Order 9C pull distribution. A node fetches an operator-published pull store:
//
//	index.json      - oktsec_pull_index.v1 (data: one entry per target)
//	index.json.sig  - oktsec_pull_index_sig.v1 (detached Ed25519 over index.json)
//	bundles/<hash>.json - the exact signed policy_bundle.v2 bytes
//
// The index is a convenience pointer, but it is SIGNED so a tampered or
// truncated index (e.g. one hiding the newest bundle) is refused rather than
// silently followed. The signature is detached and covers the LITERAL index
// bytes (not a re-canonicalization), so no shared JSON canonicalizer is needed
// between the signer (Enterprise) and this verifier — byte-exactness is the
// file's own bytes. The bundle's own signature remains the final authority for
// what is applied; the index only decides which bundle the node fetches.

const (
	// PullIndexSchemaVersion / PullIndexSigSchemaVersion are frozen schema tags.
	PullIndexSchemaVersion    = "oktsec_pull_index.v1"
	PullIndexSigSchemaVersion = "oktsec_pull_index_sig.v1"
	// pullIndexSigDomain is the domain-separation prefix of the signing payload,
	// so an index signature can never be confused with a bundle or snapshot one.
	pullIndexSigDomain = "oktsec.pull_index.v1"
)

// Pull-index reject codes, distinct from the bundle codes so an operator can
// tell an index problem from a bundle problem.
const (
	RejectPullIndexDecode      RejectCode = "pull_index_decode"
	RejectPullIndexSigInvalid  RejectCode = "pull_index_signature_invalid"
	RejectPullIndexKeyMismatch RejectCode = "pull_index_signing_key_mismatch"
)

// PullIndex is the data half (index.json). Entries map a target to the bundle
// file the node should fetch for it.
type PullIndex struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Entries       []PullIndexEntry `json:"entries"`
}

// PullIndexEntry points at one target's current bundle. The hash / sequence /
// fingerprint fields are hints the node cross-checks against the verified
// bundle; the bundle signature is the authority, so a lying entry cannot make
// the node apply something the bundle does not itself prove.
type PullIndexEntry struct {
	TargetScope          string `json:"target_scope"` // "fleet" | "node"
	TargetNodeID         string `json:"target_node_id"`
	BundleFile           string `json:"bundle_file"` // relative to the store root
	PolicyHash           string `json:"policy_hash"`
	PolicyID             string `json:"policy_id"`
	PolicyVersion        string `json:"policy_version"`
	AssignmentID         string `json:"assignment_id"`
	Sequence             int64  `json:"sequence"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// PullIndexSig is the detached signature half (index.json.sig).
type PullIndexSig struct {
	SchemaVersion        string `json:"schema_version"`
	Alg                  string `json:"alg"`
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	SignedAt             string `json:"signed_at"`
	Value                string `json:"value"`
}

// PullIndexSigningPayload is the single source of truth for the bytes an index
// signature covers. It binds the signing time and the exact index bytes (by
// their SHA-256) under a domain-separation prefix. The signer and this verifier
// MUST build it identically; a cross-repo fixture guards against drift.
func PullIndexSigningPayload(signedAt, indexSHA256Hex string) []byte {
	return []byte(pullIndexSigDomain + "\n" +
		"signed_at:" + signedAt + "\n" +
		"index_sha256:" + indexSHA256Hex)
}

// ParsePullIndex strictly decodes index.json bytes: unknown keys and trailing
// content are rejected so a node never silently ignores a field it does not
// understand.
func ParsePullIndex(raw []byte) (*PullIndex, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var idx PullIndex
	if err := dec.Decode(&idx); err != nil {
		return nil, reject(RejectPullIndexDecode, "decode index: %s", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, reject(RejectPullIndexDecode, "trailing content after index object")
	}
	if idx.SchemaVersion != PullIndexSchemaVersion {
		return nil, reject(RejectPullIndexDecode, "schema_version=%q, want %q", idx.SchemaVersion, PullIndexSchemaVersion)
	}
	return &idx, nil
}

// VerifyPullIndexSig verifies the detached signature over the literal index
// bytes against the operator-pinned trust fingerprint. Order mirrors the bundle
// verifier: decode the sig, check the key shape, prove the key is
// self-consistent (sha256(public_key)==claimed fingerprint), match the pinned
// trust fingerprint, then Ed25519-verify the domain-separated payload that binds
// the index sha256 + signed_at. The pinned fingerprint is the only trust anchor;
// nothing here is taken from the index itself.
func VerifyPullIndexSig(indexBytes, sigBytes []byte, trustFingerprint string) error {
	if trustFingerprint == "" {
		return reject(RejectPullIndexKeyMismatch, "a trust fingerprint is required to verify the pull index")
	}
	dec := json.NewDecoder(bytes.NewReader(sigBytes))
	dec.DisallowUnknownFields()
	var sig PullIndexSig
	if err := dec.Decode(&sig); err != nil {
		return reject(RejectPullIndexDecode, "decode index signature: %s", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return reject(RejectPullIndexDecode, "trailing content after index signature object")
	}
	if sig.SchemaVersion != PullIndexSigSchemaVersion {
		return reject(RejectPullIndexDecode, "sig schema_version=%q, want %q", sig.SchemaVersion, PullIndexSigSchemaVersion)
	}
	if sig.Alg != "Ed25519" {
		return reject(RejectPullIndexDecode, "sig alg=%q, want Ed25519", sig.Alg)
	}
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return reject(RejectPullIndexKeyMismatch, "sig public_key is not a valid Ed25519 key")
	}
	derivedFP := publicKeyFingerprint(ed25519.PublicKey(pub))
	if derivedFP != sig.PublicKeyFingerprint {
		return reject(RejectPullIndexKeyMismatch,
			"sig public_key_fingerprint claimed=%s computed=%s", sig.PublicKeyFingerprint, derivedFP)
	}
	if derivedFP != trustFingerprint {
		return reject(RejectPullIndexKeyMismatch,
			"index signing key %s does not match trust fingerprint %s", derivedFP, trustFingerprint)
	}
	sigVal, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil || len(sigVal) != ed25519.SignatureSize {
		return reject(RejectPullIndexSigInvalid, "sig value is not a valid Ed25519 signature")
	}
	sum := sha256.Sum256(indexBytes)
	payload := PullIndexSigningPayload(sig.SignedAt, hex.EncodeToString(sum[:]))
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sigVal) {
		return reject(RejectPullIndexSigInvalid, "index signature does not verify over the pull-index signing payload")
	}
	return nil
}

// SelectPullEntry picks the entry a node with nodeID should pull: the
// node-scoped entry if one exists, else the fleet entry. ok is false when the
// index targets neither (nothing to pull). A node-scoped entry is only eligible
// when its target_node_id equals nodeID; the bundle's own target binding is
// re-checked at apply time regardless.
func SelectPullEntry(idx *PullIndex, nodeID string) (PullIndexEntry, bool) {
	var fleet *PullIndexEntry
	for i := range idx.Entries {
		e := &idx.Entries[i]
		switch e.TargetScope {
		case "node":
			if nodeID != "" && e.TargetNodeID == nodeID {
				return *e, true
			}
		case "fleet":
			if fleet == nil {
				fleet = e
			}
		}
	}
	if fleet != nil {
		return *fleet, true
	}
	return PullIndexEntry{}, false
}

// AsRejectError unwraps a *RejectError so callers can surface its stable code.
// Returns ("", false) for a non-reject error.
func AsRejectError(err error) (RejectCode, bool) {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Code, true
	}
	return "", false
}
