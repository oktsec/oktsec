package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newTempStore returns an IdentityStore rooted in a fresh temp dir.
// Tests must never touch the real ~/.oktsec/node.
func newTempStore(t *testing.T) IdentityStore {
	t.Helper()
	return IdentityStore{Dir: filepath.Join(t.TempDir(), "node")}
}

func TestIdentityStore_StatusMissing(t *testing.T) {
	store := newTempStore(t)
	got := store.Status()
	if got.Status != "missing" {
		t.Fatalf("expected missing, got %q", got.Status)
	}
	if got.Identity != nil {
		t.Fatal("expected nil identity for missing status")
	}
	if len(got.Warnings) == 0 || got.Warnings[0].Code != WarnNodeIdentityMissing {
		t.Fatalf("expected node_identity_missing warning, got %#v", got.Warnings)
	}
}

func TestIdentityStore_InitCreatesFiles(t *testing.T) {
	store := newTempStore(t)
	id, err := store.Init(ProfileLocal)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if id.NodeID == "" || !strings.HasPrefix(id.NodeID, "node_") {
		t.Fatalf("node_id should be non-empty with node_ prefix, got %q", id.NodeID)
	}
	if id.SchemaVersion != SchemaIdentity {
		t.Fatalf("schema_version mismatch: %q", id.SchemaVersion)
	}
	if id.InstallProfile != ProfileLocal {
		t.Fatalf("profile mismatch: %q", id.InstallProfile)
	}
	if !strings.HasPrefix(id.PublicKeyFingerprint, "sha256:") {
		t.Fatalf("public key fingerprint must be sha256-prefixed, got %q", id.PublicKeyFingerprint)
	}
	if !strings.HasPrefix(id.HostFingerprint, "sha256:") {
		t.Fatalf("host fingerprint must be sha256-prefixed, got %q", id.HostFingerprint)
	}
	for _, name := range []string{identityFileName, privateKeyFile, publicKeyFile} {
		path := filepath.Join(store.Dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected file %s, got %v", name, err)
		}
	}
}

func TestIdentityStore_InitIsIdempotent(t *testing.T) {
	store := newTempStore(t)
	first, err := store.Init(ProfileLocal)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}
	second, err := store.Init(ProfileLocal)
	if err != nil {
		t.Fatalf("second init: %v", err)
	}
	if first.NodeID != second.NodeID {
		t.Fatalf("idempotent init produced new node id: %q vs %q", first.NodeID, second.NodeID)
	}
}

func TestIdentityStore_InitUpdatesProfileOnly(t *testing.T) {
	store := newTempStore(t)
	first, err := store.Init(ProfileLocal)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}
	second, err := store.Init(ProfileEnterprise)
	if err != nil {
		t.Fatalf("second init: %v", err)
	}
	if second.NodeID != first.NodeID {
		t.Fatalf("profile change must not rotate node id")
	}
	if second.InstallProfile != ProfileEnterprise {
		t.Fatalf("expected enterprise profile after re-init, got %q", second.InstallProfile)
	}
}

func TestIdentityStore_PrivateKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics do not apply on Windows")
	}
	store := newTempStore(t)
	if _, err := store.Init(ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	info, err := os.Stat(filepath.Join(store.Dir, privateKeyFile))
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("private key must be 0600, got %o", mode)
	}
	info, err = os.Stat(filepath.Join(store.Dir, publicKeyFile))
	if err != nil {
		t.Fatalf("stat public key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("public key should be 0644, got %o", mode)
	}
	info, err = os.Stat(store.Dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("identity dir should be 0700, got %o", mode)
	}
}

func TestIdentityStore_IdentityJSONHasNoSecret(t *testing.T) {
	store := newTempStore(t)
	if _, err := store.Init(ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(store.Dir, identityFileName))
	if err != nil {
		t.Fatalf("read identity.json: %v", err)
	}
	// Decode as raw map so we don't pre-restrict the fields.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("identity.json must be valid JSON: %v", err)
	}
	// Reject any field that looks key-shaped.
	for k := range raw {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "private") || lower == "secret" || lower == "key" {
			t.Fatalf("identity.json must not contain private/secret material: %s", k)
		}
	}
	if strings.Contains(string(data), "BEGIN") {
		t.Fatalf("identity.json must not contain PEM blocks")
	}
}

func TestIdentityStore_SignVerify(t *testing.T) {
	store := newTempStore(t)
	id, err := store.Init(ProfileLocal)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	pub, err := store.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if fingerprintPublicKey(pub) != id.PublicKeyFingerprint {
		t.Fatalf("fingerprint mismatch between identity.json and on-disk key")
	}
	payload := []byte("hello-node-snapshot")
	sig, err := store.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw := decodeBase64OrFail(t, sig.Base64)
	if !ed25519.Verify(pub, payload, raw) {
		t.Fatalf("signature did not verify against the stored public key")
	}
}

func TestIdentityStore_RejectsSymlinkedIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	store := newTempStore(t)
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Plant a symlink at identity.json pointing at a real file
	// elsewhere; Load() must refuse to read it.
	other := filepath.Join(t.TempDir(), "decoy.json")
	if err := os.WriteFile(other, []byte(`{"node_id":"node_x","schema_version":"node_identity.v1","install_profile":"local"}`), 0o600); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	if err := os.Symlink(other, filepath.Join(store.Dir, identityFileName)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("Load() should reject symlinked identity.json")
	}
}

func TestIdentityStore_RejectsSymlinkedNodeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	linkDir := filepath.Join(parent, "linked")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	store := IdentityStore{Dir: linkDir}
	if _, err := store.Init(ProfileLocal); err == nil {
		t.Fatal("Init must refuse symlinked node directory")
	}
}

func TestIdentityStore_IdentityJSONOnlyIsInvalid(t *testing.T) {
	// Regression: future Enterprise relies on signed checkpoints.
	// An identity.json without the corresponding node.key/node.pub
	// must report as invalid, not present, otherwise `node status`
	// lies about whether this node can sign anything.
	store := newTempStore(t)
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := `{
		"schema_version": "node_identity.v1",
		"node_id": "node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"created_at": "2026-05-21T00:00:00Z",
		"public_key_fingerprint": "sha256:deadbeef",
		"host_fingerprint": "sha256:cafebabe",
		"install_profile": "local"
	}`
	if err := os.WriteFile(filepath.Join(store.Dir, identityFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("write identity.json: %v", err)
	}
	got := store.Status()
	if got.Status != "invalid" {
		t.Fatalf("identity.json without keys must be invalid, got %q", got.Status)
	}
	if got.Identity != nil {
		t.Fatalf("invalid identity should not expose identity payload")
	}
}

func TestIdentityStore_MismatchedKeyIsInvalid(t *testing.T) {
	// Regression: identity.json fingerprint must match the actual
	// public key on disk. A mismatched pair cannot sign anything.
	store := newTempStore(t)
	if _, err := store.Init(ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Replace the public key with a different one — the fingerprint
	// in identity.json will no longer match.
	otherStore := newTempStore(t)
	if _, err := otherStore.Init(ProfileLocal); err != nil {
		t.Fatalf("init other: %v", err)
	}
	otherPub, err := os.ReadFile(filepath.Join(otherStore.Dir, publicKeyFile))
	if err != nil {
		t.Fatalf("read other pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, publicKeyFile), otherPub, 0o644); err != nil {
		t.Fatalf("overwrite pub: %v", err)
	}
	got := store.Status()
	if got.Status != "invalid" {
		t.Fatalf("mismatched pub/priv must be invalid, got %q", got.Status)
	}
}

func TestIdentityStore_MissingPrivateKeyIsInvalid(t *testing.T) {
	store := newTempStore(t)
	if _, err := store.Init(ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := os.Remove(filepath.Join(store.Dir, privateKeyFile)); err != nil {
		t.Fatalf("remove private: %v", err)
	}
	got := store.Status()
	if got.Status != "invalid" {
		t.Fatalf("missing private key must be invalid, got %q", got.Status)
	}
}

func TestIdentityStore_LoadRejectsAgentPEM(t *testing.T) {
	// A node store must never accept a key written by the agent
	// identity package (which uses "OKTSEC ED25519 PRIVATE KEY"
	// without the NODE qualifier).
	store := newTempStore(t)
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bad := "-----BEGIN OKTSEC ED25519 PRIVATE KEY-----\nAAAA\n-----END OKTSEC ED25519 PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(store.Dir, privateKeyFile), []byte(bad), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	if _, err := readPrivateKey(filepath.Join(store.Dir, privateKeyFile)); err == nil {
		t.Fatal("expected agent-PEM key to be refused")
	}
}

// decodeBase64OrFail uses the std library and t.Fatal on error.
func decodeBase64OrFail(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(out) != ed25519.SignatureSize {
		t.Fatalf("unexpected sig length %d", len(out))
	}
	return out
}
