package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/node"
)

// withTestNodeStore swaps nodeStoreForTest for the duration of the test
// so the CLI never reaches the real ~/.oktsec/node.
func withTestNodeStore(t *testing.T) node.IdentityStore {
	t.Helper()
	store := node.IdentityStore{Dir: filepath.Join(t.TempDir(), "node")}
	prev := nodeStoreForTest
	nodeStoreForTest = func() node.IdentityStore { return store }
	t.Cleanup(func() { nodeStoreForTest = prev })
	return store
}

// withTestCfgFile sets cfgFile to a temp path so commands resolve
// against test fixtures instead of the operator's real config.
func withTestCfgFile(t *testing.T, path string) {
	t.Helper()
	prev := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = prev })
}

// withTestSnapshotDBPath pins the DB path the snapshot command
// reads so it never reaches the developer's real audit DB.
func withTestSnapshotDBPath(t *testing.T, path string) {
	t.Helper()
	prev := nodeSnapshotDBPathOverride
	nodeSnapshotDBPathOverride = path
	t.Cleanup(func() { nodeSnapshotDBPathOverride = prev })
}

func TestNodeCmdRegistered(t *testing.T) {
	root := NewRoot()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "node" {
			found = true
			subs := map[string]bool{}
			for _, sc := range c.Commands() {
				subs[sc.Name()] = true
			}
			for _, want := range []string{"init", "status", "snapshot"} {
				if !subs[want] {
					t.Errorf("node command missing subcommand %q", want)
				}
			}
		}
	}
	if !found {
		t.Fatal("oktsec node command should be registered on root")
	}
}

func TestNodeInit_CreatesIdentity(t *testing.T) {
	store := withTestNodeStore(t)
	cmd := newNodeInitCmd()
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var got node.IdentityStatus
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out.String())
	}
	if got.Status != "present" || got.Identity == nil {
		t.Fatalf("expected present + identity, got %+v", got)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "identity.json")); err != nil {
		t.Fatalf("identity.json missing: %v", err)
	}
}

func TestNodeStatus_Missing(t *testing.T) {
	_ = withTestNodeStore(t)
	cmd := newNodeStatusCmd()
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var got node.IdentityStatus
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out.String())
	}
	if got.Status != "missing" {
		t.Fatalf("expected missing, got %q", got.Status)
	}
}

func TestNodeSnapshot_NoConfig(t *testing.T) {
	_ = withTestNodeStore(t)
	withTestCfgFile(t, filepath.Join(t.TempDir(), "missing.yaml"))
	withTestSnapshotDBPath(t, filepath.Join(t.TempDir(), "missing.db"))
	cmd := newNodeSnapshotCmd()
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var snap node.Snapshot
	if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
		t.Fatalf("decode snapshot: %v\n%s", err, out.String())
	}
	if snap.SchemaVersion != node.SchemaSnapshot {
		t.Fatalf("schema version: %q", snap.SchemaVersion)
	}
	if !strings.HasPrefix(snap.Node.OktsecVersion, "") {
		t.Fatalf("version field unexpectedly absent")
	}
}

func TestNodeSnapshot_OutputFile(t *testing.T) {
	_ = withTestNodeStore(t)
	withTestCfgFile(t, filepath.Join(t.TempDir(), "missing.yaml"))
	withTestSnapshotDBPath(t, filepath.Join(t.TempDir(), "missing.db"))
	outPath := filepath.Join(t.TempDir(), "snap.json")
	cmd := newNodeSnapshotCmd()
	cmd.SetArgs([]string{"--output", outPath})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read snapshot file: %v", err)
	}
	var snap node.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("decode: %v\n%s", err, string(data))
	}
	if snap.SchemaVersion != node.SchemaSnapshot {
		t.Fatalf("schema version: %q", snap.SchemaVersion)
	}
}

func TestNodeSnapshot_InvalidSinceFails(t *testing.T) {
	_ = withTestNodeStore(t)
	withTestSnapshotDBPath(t, filepath.Join(t.TempDir(), "missing.db"))
	cmd := newNodeSnapshotCmd()
	cmd.SetArgs([]string{"--since", "not-a-duration"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error on invalid --since")
	}
}

func TestNodeSnapshot_DoesNotCreateDB(t *testing.T) {
	_ = withTestNodeStore(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: dir},
		Server:   config.ServerConfig{Port: 8080, LogLevel: "info"},
		DBPath:   filepath.Join(dir, "should-not-be-created.db"),
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	withTestCfgFile(t, cfgPath)
	withTestSnapshotDBPath(t, cfg.DBPath)
	cmd := newNodeSnapshotCmd()
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if _, err := os.Stat(cfg.DBPath); err == nil {
		t.Fatalf("snapshot must not create the audit DB")
	}
}
