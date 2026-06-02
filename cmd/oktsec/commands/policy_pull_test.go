package commands

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/policybundle"
)

func runPolicyPull(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	root := NewRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"policy", "pull"}, args...))
	err := root.Execute()
	var got map[string]any
	if out.Len() > 0 {
		_ = json.Unmarshal(out.Bytes(), &got)
	}
	return got, err
}

// signPullIndex builds a valid index.json.sig over indexBytes using the same
// deterministic key signV2Bundle uses, so one trust fingerprint verifies both
// the index and the bundles.
func signPullIndex(t *testing.T, indexBytes []byte) []byte {
	t.Helper()
	priv, fp := v2SignerKey(t)
	sum := sha256.Sum256(indexBytes)
	payload := policybundle.PullIndexSigningPayload("2026-06-01T12:00:00Z", hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(priv, payload)
	out, err := json.Marshal(policybundle.PullIndexSig{
		SchemaVersion:        policybundle.PullIndexSigSchemaVersion,
		Alg:                  "Ed25519",
		PublicKey:            base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		PublicKeyFingerprint: fp,
		SignedAt:             "2026-06-01T12:00:00Z",
		Value:                base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal index sig: %v", err)
	}
	return out
}

// writePullStore lays out <dir>/bundles/<name>.json + index.json + index.json.sig
// for one entry, and returns the store dir. entryNodeID/"" selects the entry's
// scope (node vs fleet). indexMut lets a test corrupt the index before signing.
func writePullStore(t *testing.T, bundleRaw []byte, entryScope, entryNodeID, bundleFile string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bundles"), 0o700); err != nil {
		t.Fatalf("mkdir bundles: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(bundleFile)), bundleRaw, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	// Derive the index entry from the bundle so the signed index BINDS the exact
	// bundle (hash + assignment + sequence). The caller's entryScope/entryNodeID
	// is the entry's CLAIMED target, which a test can deliberately set to differ
	// from the bundle's to exercise the binding check.
	var b policybundle.PolicyBundleV2
	if err := json.Unmarshal(bundleRaw, &b); err != nil {
		t.Fatalf("unmarshal bundle for index: %v", err)
	}
	idx, err := json.Marshal(policybundle.PullIndex{
		SchemaVersion: policybundle.PullIndexSchemaVersion,
		GeneratedAt:   "2026-06-01T12:00:00Z",
		Entries: []policybundle.PullIndexEntry{{
			TargetScope: entryScope, TargetNodeID: entryNodeID, BundleFile: bundleFile,
			PolicyHash: b.PolicyHash, PolicyID: b.Policy.PolicyID, PolicyVersion: b.Policy.PolicyVersion,
			AssignmentID: b.Policy.Assignment.AssignmentID, Sequence: b.Policy.Assignment.Sequence,
			PublicKeyFingerprint: b.Signature.PublicKeyFingerprint,
		}},
	})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json.sig"), signPullIndex(t, idx), 0o600); err != nil {
		t.Fatalf("write index sig: %v", err)
	}
	return dir
}

func fileURL(dir string) string { return "file://" + dir }

func TestPolicyPull_FetchesAndApplies(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("node", "node_x"))
	store := writePullStore(t, raw, "node", "node_x", "bundles/b.json")

	// Dry-run writes nothing.
	before, _ := os.ReadFile(configPath)
	if _, err := runPolicyPull(t, "--source", fileURL(store), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--dry-run", "--json"); err != nil {
		t.Fatalf("dry-run pull: %v", err)
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run must not write the config")
	}

	// Real apply writes the config + records state.
	got, err := runPolicyPull(t, "--source", fileURL(store), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json")
	if err != nil {
		t.Fatalf("apply pull: %v", err)
	}
	if got["applied"] != true {
		t.Fatalf("expected applied=true, got %v", got)
	}
	if _, err := os.Stat(statePath(configPath)); err != nil {
		t.Fatalf("anti-rollback state must be written: %v", err)
	}
}

func TestPolicyPull_StaleSequenceRejected(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	// Bundle at sequence 2 applies and sets the anti-rollback floor.
	hi := supportedAgentBodyV2("node", "node_x")
	hi.Assignment.Sequence = 2
	hi.Assignment.AssignmentID = "assign-2"
	rawHi, fp := signV2Bundle(t, hi)
	storeHi := writePullStore(t, rawHi, "node", "node_x", "bundles/hi.json")
	if got, err := runPolicyPull(t, "--source", fileURL(storeHi), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err != nil || got["applied"] != true {
		t.Fatalf("seq2 must apply: err=%v got=%v", err, got)
	}

	// A store offering sequence 1 for the same target must be refused.
	lo := supportedAgentBodyV2("node", "node_x")
	lo.Assignment.Sequence = 1
	lo.Assignment.AssignmentID = "assign-1"
	rawLo, _ := signV2Bundle(t, lo)
	storeLo := writePullStore(t, rawLo, "node", "node_x", "bundles/lo.json")
	if _, err := runPolicyPull(t, "--source", fileURL(storeLo), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err == nil {
		t.Fatal("a stale (lower-sequence) bundle must be refused by anti-rollback")
	}
}

func TestPolicyPull_WrongTargetRejected(t *testing.T) {
	// The index entry claims node_x, but the bundle is bound to node_other.
	// The bundle is the authority: pull --node-id node_x must fail target binding.
	_, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("node", "node_other"))
	store := writePullStore(t, raw, "node", "node_x", "bundles/b.json")

	got, err := runPolicyPull(t, "--source", fileURL(store), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json")
	if err == nil {
		t.Fatal("a bundle bound to a different node must be refused")
	}
	if got["applied"] == true {
		t.Fatalf("must not apply a wrong-target bundle: %v", got)
	}
}

func TestPolicyPull_SubstitutedBundleRejected(t *testing.T) {
	// The signed index names bundle A, but the file at that path is a DIFFERENT
	// validly-signed bundle B (same key). Even on a fresh node with no
	// anti-rollback floor, the signed index must bind the exact bundle: B is
	// refused because it does not match the entry A names.
	_, configPath := writeV2ApplyConfig(t)
	rawA, fp := signV2Bundle(t, supportedAgentBodyV2("fleet", ""))
	bodyB := supportedAgentBodyV2("fleet", "")
	bodyB.PolicyVersion = "2"
	bodyB.Assignment.AssignmentID = "assign-B"
	rawB, _ := signV2Bundle(t, bodyB)

	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "bundles"), 0o700)
	var a policybundle.PolicyBundleV2
	if err := json.Unmarshal(rawA, &a); err != nil {
		t.Fatalf("unmarshal A: %v", err)
	}
	idx, _ := json.Marshal(policybundle.PullIndex{
		SchemaVersion: policybundle.PullIndexSchemaVersion,
		GeneratedAt:   "2026-06-01T12:00:00Z",
		Entries: []policybundle.PullIndexEntry{{
			TargetScope: "fleet", BundleFile: "bundles/b.json",
			PolicyHash: a.PolicyHash, PolicyID: a.Policy.PolicyID, PolicyVersion: a.Policy.PolicyVersion,
			AssignmentID: a.Policy.Assignment.AssignmentID, Sequence: a.Policy.Assignment.Sequence,
		}},
	})
	_ = os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "index.json.sig"), signPullIndex(t, idx), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bundles", "b.json"), rawB, 0o600) // substituted

	if _, err := runPolicyPull(t, "--source", fileURL(dir), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err == nil {
		t.Fatal("a bundle not matching the signed index entry must be refused")
	}
}

func TestPolicyPull_TamperedBundleRejected(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("fleet", ""))
	// Build the (signed) index from the valid bundle, then corrupt the bundle
	// bytes on disk so its signature no longer verifies.
	store := writePullStore(t, raw, "fleet", "", "bundles/b.json")
	bundlePath := filepath.Join(store, "bundles", "b.json")
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x01
	if err := os.WriteFile(bundlePath, tampered, 0o600); err != nil {
		t.Fatalf("rewrite tampered bundle: %v", err)
	}

	if _, err := runPolicyPull(t, "--source", fileURL(store), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err == nil {
		t.Fatal("a tampered bundle must be refused")
	}
}

func TestPolicyPull_TamperedIndexRejected(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("fleet", ""))
	store := writePullStore(t, raw, "fleet", "", "bundles/b.json")
	// Flip a byte of index.json AFTER it was signed.
	idxPath := filepath.Join(store, "index.json")
	idx, _ := os.ReadFile(idxPath)
	idx[len(idx)/2] ^= 0x01
	if err := os.WriteFile(idxPath, idx, 0o600); err != nil {
		t.Fatalf("rewrite tampered index: %v", err)
	}
	if _, err := runPolicyPull(t, "--source", fileURL(store), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err == nil {
		t.Fatal("a tampered index must be refused before any bundle fetch")
	}
}

func TestPolicyPull_WrongIndexSigningKeyRejected(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	raw, _ := signV2Bundle(t, supportedAgentBodyV2("fleet", ""))
	store := writePullStore(t, raw, "fleet", "", "bundles/b.json")
	// Pin a trust fingerprint that does not match the signing key.
	if _, err := runPolicyPull(t, "--source", fileURL(store), "--node-id", "node_x",
		"--trust-fingerprint", "sha256:"+hex.EncodeToString(make([]byte, 32)),
		"--config", configPath, "--json"); err == nil {
		t.Fatal("an index signed by a non-pinned key must be refused")
	}
}

func TestPolicyPull_PathTraversalBundleFileRejected(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("fleet", ""))
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "bundles"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "bundles", "b.json"), raw, 0o600)
	idx, _ := json.Marshal(policybundle.PullIndex{
		SchemaVersion: policybundle.PullIndexSchemaVersion,
		GeneratedAt:   "2026-06-01T12:00:00Z",
		Entries: []policybundle.PullIndexEntry{
			{TargetScope: "fleet", BundleFile: "../escape.json", PolicyHash: "sha256:x", Sequence: 1},
		},
	})
	_ = os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "index.json.sig"), signPullIndex(t, idx), 0o600)

	if _, err := runPolicyPull(t, "--source", fileURL(dir), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err == nil {
		t.Fatal("a traversal bundle_file must be refused")
	}
}

func TestPolicyPull_NoTargetEntry(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	dir := t.TempDir()
	idx, _ := json.Marshal(policybundle.PullIndex{
		SchemaVersion: policybundle.PullIndexSchemaVersion,
		GeneratedAt:   "2026-06-01T12:00:00Z",
		Entries:       []policybundle.PullIndexEntry{}, // nothing for anyone
	})
	_ = os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "index.json.sig"), signPullIndex(t, idx), 0o600)
	_, fp := v2SignerKey(t)

	got, err := runPolicyPull(t, "--source", fileURL(dir), "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json")
	if err != nil {
		t.Fatalf("empty index is not an error: %v", err)
	}
	if got["pulled"] != false {
		t.Fatalf("expected pulled=false for no target, got %v", got)
	}
}

func TestPolicyPull_HTTPSFetch(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("node", "node_x"))
	store := writePullStore(t, raw, "node", "node_x", "bundles/b.json")
	srv := httptest.NewServer(http.FileServer(http.Dir(store)))
	defer srv.Close()

	// SafeDialContext blocks loopback, so point the fetcher's dialer at the
	// local test server for this case (prod keeps SafeDialContext).
	orig := pullDialContext
	pullDialContext = (&net.Dialer{}).DialContext
	defer func() { pullDialContext = orig }()

	got, err := runPolicyPull(t, "--source", srv.URL, "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json")
	if err != nil {
		t.Fatalf("https pull: %v", err)
	}
	if got["applied"] != true {
		t.Fatalf("expected applied=true over https, got %v", got)
	}
}

func TestPolicyPull_HTTPOverlargeObjectRejected(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	_, fp := v2SignerKey(t)
	// Serve an index.json larger than the cap; the fetch must reject it rather
	// than verify a truncated prefix.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), (1<<20)+10))
	}))
	defer srv.Close()
	orig := pullDialContext
	pullDialContext = (&net.Dialer{}).DialContext
	defer func() { pullDialContext = orig }()

	if _, err := runPolicyPull(t, "--source", srv.URL, "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json"); err == nil {
		t.Fatal("an over-cap HTTP object must be rejected, not truncated")
	}
}

func TestPolicyPull_SSRFGuardBlocksLoopback(t *testing.T) {
	_, configPath := writeV2ApplyConfig(t)
	_, fp := v2SignerKey(t)
	// Default dialer (SafeDialContext) must refuse a loopback store URL.
	_, err := runPolicyPull(t, "--source", "http://127.0.0.1:9/", "--node-id", "node_x",
		"--trust-fingerprint", fp, "--config", configPath, "--json")
	if err == nil {
		t.Fatal("the SSRF guard must refuse a loopback source")
	}
}
