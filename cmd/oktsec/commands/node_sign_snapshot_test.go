package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/node"
)

// stagedSnapshot writes a minimal-but-real node_snapshot.v1 JSON
// file matching the IdentityStore the test injected. The returned
// path is the path the sign-snapshot CLI receives via --snapshot.
// Centralizing the fixture here means every CLI test runs against
// the same baseline shape; specific tests mutate the file post-write
// when they need to exercise an error path.
func stagedSnapshot(t *testing.T, dir string, store node.IdentityStore) (path string, id *node.Identity) {
	t.Helper()
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	snap := node.Snapshot{
		SchemaVersion: node.SchemaSnapshot,
		GeneratedAt:   "2026-05-22T00:00:00Z",
		Range:         node.SnapshotRange{Since: "2026-05-21T00:00:00Z"},
		Node: node.SnapshotNode{
			NodeID:               loaded.NodeID,
			IdentityStatus:       "present",
			HostFingerprint:      loaded.HostFingerprint,
			PublicKeyFingerprint: loaded.PublicKeyFingerprint,
			GOOS:                 "linux",
			GOARCH:               "amd64",
			Profile:              node.ProfileLocal,
		},
		Config:    node.SnapshotConfig{Status: "missing"},
		Inventory: node.SnapshotInventory{},
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	path = filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	return path, loaded
}

// runSignSnapshot executes `node sign-snapshot` with the given args
// and returns combined stdout/stderr. The test caller pre-injects
// nodeStoreForTest so the command finds the seeded identity.
func runSignSnapshot(t *testing.T, args []string) (string, error) {
	t.Helper()
	cmd := newNodeSignSnapshotCmd()
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

func TestSignSnapshotCLI_OutputFileHasOwnerOnlyPerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}
	store := withTestNodeStore(t)
	if _, err := store.Init(node.ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	dir := t.TempDir()
	snapPath, id := stagedSnapshot(t, dir, store)
	outPath := filepath.Join(dir, "out.envelope.json")
	out, err := runSignSnapshot(t, []string{"--snapshot", snapPath, "--output", outPath})
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("output perm = %o, want 0o600", perm)
	}
	// Re-read and confirm we wrote a recognizable envelope for
	// the seeded identity.
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var env node.SnapshotEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("envelope parse: %v\n%s", err, body)
	}
	if env.SchemaVersion != node.SchemaSnapshotEnvelope ||
		env.NodeID != id.NodeID {
		t.Fatalf("envelope shape wrong: %+v", env)
	}
}

func TestSignSnapshotCLI_StdoutWhenNoOutputFlag(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init(node.ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	dir := t.TempDir()
	snapPath, id := stagedSnapshot(t, dir, store)
	out, err := runSignSnapshot(t, []string{"--snapshot", snapPath})
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	// Output must be parseable JSON — nothing else can be
	// interleaved (no human-prose log lines).
	var env node.SnapshotEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("stdout must be pure JSON: %v\n%s", err, out)
	}
	if env.NodeID != id.NodeID {
		t.Fatalf("envelope node_id wrong: %q vs %q", env.NodeID, id.NodeID)
	}
	if env.Signature.PublicKey == "" {
		t.Fatalf("envelope signature is missing public_key")
	}
	if _, err := base64.StdEncoding.DecodeString(env.Signature.PublicKey); err != nil {
		t.Fatalf("envelope public_key not std-base64: %v", err)
	}
}

func TestSignSnapshotCLI_RefusesSymlinkSnapshotInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	store := withTestNodeStore(t)
	if _, err := store.Init(node.ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	dir := t.TempDir()
	realPath, _ := stagedSnapshot(t, dir, store)
	linkPath := filepath.Join(dir, "link.json")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	out, err := runSignSnapshot(t, []string{"--snapshot", linkPath})
	if err == nil {
		t.Fatalf("expected refusal for symlinked input; output:\n%s", out)
	}
	if !strings.Contains(err.Error(), "symbolic link") &&
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error should mention symlink: %v", err)
	}
}

func TestSignSnapshotCLI_RefusesSymlinkOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	store := withTestNodeStore(t)
	if _, err := store.Init(node.ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	dir := t.TempDir()
	snapPath, _ := stagedSnapshot(t, dir, store)
	realOut := filepath.Join(dir, "real.json")
	if err := os.WriteFile(realOut, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("placeholder: %v", err)
	}
	linkOut := filepath.Join(dir, "out.envelope.json")
	if err := os.Symlink(realOut, linkOut); err != nil {
		t.Fatalf("symlink output: %v", err)
	}
	out, err := runSignSnapshot(t, []string{"--snapshot", snapPath, "--output", linkOut})
	if err == nil {
		t.Fatalf("expected refusal for symlinked output; output:\n%s", out)
	}
}

func TestSignSnapshotCLI_RejectsUnknownFields(t *testing.T) {
	// The reviewer caveat: the signed path must NEVER tolerate
	// unknown fields silently. Hand-edit a real snapshot to add
	// an `extra` field at top level — DisallowUnknownFields
	// must refuse it BEFORE we canonicalize and sign, otherwise
	// the envelope would cover a subset of the artifact.
	store := withTestNodeStore(t)
	if _, err := store.Init(node.ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	dir := t.TempDir()
	snapPath, _ := stagedSnapshot(t, dir, store)
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode: %v", err)
	}
	generic["extra"] = "would-be-silently-dropped"
	modified, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(snapPath, modified, 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	out, err := runSignSnapshot(t, []string{"--snapshot", snapPath})
	if err == nil {
		t.Fatalf("unknown-field snapshot must refuse signing; output:\n%s", out)
	}
}

func TestSignSnapshotCLI_RejectsBadSchemaVersion(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init(node.ProfileLocal); err != nil {
		t.Fatalf("init: %v", err)
	}
	dir := t.TempDir()
	snapPath, _ := stagedSnapshot(t, dir, store)
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode: %v", err)
	}
	generic["schema_version"] = "node_snapshot.v0"
	modified, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(snapPath, modified, 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	out, err := runSignSnapshot(t, []string{"--snapshot", snapPath})
	if err == nil {
		t.Fatalf("wrong schema_version must refuse signing; output:\n%s", out)
	}
}

func TestSignSnapshotCLI_RegisteredOnNodeGroup(t *testing.T) {
	// Make sure `oktsec node sign-snapshot` is actually wired
	// up under the node command tree.
	root := NewRoot()
	for _, c := range root.Commands() {
		if c.Name() != "node" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "sign-snapshot" {
				return
			}
		}
	}
	t.Fatalf("sign-snapshot subcommand not registered under `oktsec node`")
}
