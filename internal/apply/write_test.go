package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// origConfigYAML is a minimal valid config with a voice-ai agent, written
// verbatim so the backup assertion can compare exact bytes (comment included).
const origConfigYAML = `# operator config
version: "1"
server:
  port: 8080
identity:
  require_signature: false
agents:
  voice-ai:
    allowed_tools: [old.tool]
rules: []
`

// writeOrigConfig drops origConfigYAML into a temp dir and returns its path.
func writeOrigConfig(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(origConfigYAML), mode); err != nil {
		t.Fatalf("write original config: %v", err)
	}
	return path
}

// planWithChanges builds a real projection plan (tools change) for the config
// at path, so Commit has something to write.
func planWithChanges(t *testing.T, path string) *Plan {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	b := body()
	b.Gateway.ToolsAllowed = []string{"calendar.read", "voice.dial"}
	p, err := DryRun(verified(b), cfg, "voice-ai", path)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if len(p.Changes) == 0 {
		t.Fatal("test setup: plan must have changes")
	}
	return p
}

func TestCommit_WritesBacksUpAndPreservesMode(t *testing.T) {
	path := writeOrigConfig(t, 0o600)
	orig, _ := os.ReadFile(path)
	plan := planWithChanges(t, path)

	backupPath, err := Commit(plan, path)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Backup is the exact original bytes, in the same directory.
	if filepath.Dir(backupPath) != filepath.Dir(path) {
		t.Fatalf("backup not in config dir: %q", backupPath)
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != origConfigYAML {
		t.Fatal("backup is not the exact original bytes")
	}

	// Config was rewritten, loads, validates, and reflects the projection.
	after, _ := os.ReadFile(path)
	if string(after) == origConfigYAML {
		t.Fatal("Commit did not rewrite the config")
	}
	written, err := config.Load(path)
	if err != nil {
		t.Fatalf("written config must load: %v", err)
	}
	if err := written.Validate(); err != nil {
		t.Fatalf("written config must validate: %v", err)
	}
	va := written.Agents["voice-ai"]
	if len(va.AllowedTools) != 2 || va.AllowedTools[0] != "calendar.read" {
		t.Fatalf("written allowed tools = %v", va.AllowedTools)
	}

	// Mode preserved.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600", info.Mode().Perm())
	}

	// Only governed sections change: load-time defaults the operator never
	// wrote (e.g. db_path) must NOT be persisted, and untouched content (the
	// header comment) survives.
	if strings.Contains(string(after), "db_path") {
		t.Fatal("apply persisted a load-time default (db_path) the original lacked")
	}
	if !strings.Contains(string(after), "operator config") {
		t.Fatal("apply dropped an unrelated header comment")
	}
	_ = orig
}

func TestCommit_NilProjectionIsError(t *testing.T) {
	if _, err := Commit(&Plan{}, "ignored"); !errors.Is(err, ErrNoProjection) {
		t.Fatalf("err = %v, want ErrNoProjection", err)
	}
}

func TestCommit_InvalidPatchedConfigRejectedNoMutation(t *testing.T) {
	// If the patched result would not validate, Commit must refuse before
	// touching the config or leaving a backup. A hand-built plan injects an
	// invalid rule action into the projection that the patch would write.
	path := writeOrigConfig(t, 0o600)
	orig, _ := os.ReadFile(path)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.Rules = []config.RuleAction{{ID: "X", Action: "not-a-valid-action"}}
	plan := &Plan{
		Agent:     "voice-ai",
		Changes:   []Change{{Kind: "rule_override", ID: "X", Action: "not-a-valid-action"}},
		projected: cfg,
	}

	if _, err := Commit(plan, path); err == nil {
		t.Fatal("Commit must reject an invalid patched config")
	}
	if after, _ := os.ReadFile(path); string(after) != string(orig) {
		t.Fatal("config mutated despite an invalid patched result")
	}
	// Validation fails before the backup, so no stray files beside the config.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 || entries[0].Name() != "oktsec.yaml" {
		t.Fatalf("stray files after rejected apply: %v", entries)
	}
}

func TestCommit_SymlinkConfigRejectedNoWrite(t *testing.T) {
	path := writeOrigConfig(t, 0o600)
	plan := planWithChanges(t, path)

	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	orig, _ := os.ReadFile(path)

	if _, err := Commit(plan, link); err == nil {
		t.Fatal("Commit must reject a symlink config path")
	}
	// The real target must be untouched, and no backup created beside it.
	after, _ := os.ReadFile(path)
	if string(after) != string(orig) {
		t.Fatal("Commit wrote through a symlink to the target")
	}
}

func TestCommit_ReadOnlyConfigRejectedNoMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permission bits")
	}
	path := writeOrigConfig(t, 0o400) // read-only
	orig, _ := os.ReadFile(path)
	plan := planWithChanges(t, path)

	if _, err := Commit(plan, path); err == nil {
		t.Fatal("Commit must refuse a read-only config")
	}
	if after, _ := os.ReadFile(path); string(after) != string(orig) {
		t.Fatal("read-only config was mutated")
	}
}

func TestCommit_AliasAgentRejectedNoMutation(t *testing.T) {
	// An agent written as a YAML alias resolves at load time, but rewriting it
	// would drop the inherited fields — Commit must refuse, not nuke them.
	const aliasYAML = `version: "1"
server:
  port: 8080
identity:
  require_signature: false
defaults: &defaults
  allowed_tools: [old.tool]
agents:
  voice-ai: *defaults
rules: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(aliasYAML), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	orig, _ := os.ReadFile(path)
	plan := planWithChanges(t, path) // changes the agent's allowed_tools

	if _, err := Commit(plan, path); err == nil {
		t.Fatal("Commit must refuse to patch a YAML-alias agent")
	}
	if after, _ := os.ReadFile(path); string(after) != string(orig) {
		t.Fatal("alias-agent config was mutated")
	}
}

func TestBackupOriginal_CollisionStaysUnique(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Two backups (likely the same second) must both succeed with distinct
	// names — a backup-name clash never aborts a valid apply.
	b1, err := backupOriginal(path, []byte("one"), 0o600)
	if err != nil {
		t.Fatalf("backup 1: %v", err)
	}
	b2, err := backupOriginal(path, []byte("two"), 0o600)
	if err != nil {
		t.Fatalf("backup 2: %v", err)
	}
	if b1 == b2 {
		t.Fatalf("backups collided: both %q", b1)
	}
	for _, b := range []string{b1, b2} {
		if _, err := os.Stat(b); err != nil {
			t.Fatalf("backup %q missing: %v", b, err)
		}
	}
}

func TestWriteExclusive_RefusesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backup")
	if err := os.WriteFile(path, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// O_EXCL must refuse to clobber an existing file (the backup-collision and
	// existing-symlink guarantees both rely on this).
	if err := writeExclusive(path, []byte("new"), 0o600); err == nil {
		t.Fatal("writeExclusive must refuse an existing target")
	}
	if got, _ := os.ReadFile(path); string(got) != "pre-existing" {
		t.Fatal("writeExclusive clobbered an existing file")
	}
}

func TestCommit_NoStrayTempAfterApply(t *testing.T) {
	// A successful apply leaves exactly the config + one backup, no temp files.
	path := writeOrigConfig(t, 0o600)
	plan := planWithChanges(t, path)
	if _, err := Commit(plan, path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatalf("want config + backup only, got %v", entries)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("stray temp file left behind: %s", e.Name())
		}
	}
}
