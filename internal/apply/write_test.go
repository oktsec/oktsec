package apply

import (
	"errors"
	"os"
	"path/filepath"
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
	_ = orig
}

func TestCommit_NilProjectionIsError(t *testing.T) {
	if _, err := Commit(&Plan{}, "ignored"); !errors.Is(err, ErrNoProjection) {
		t.Fatalf("err = %v, want ErrNoProjection", err)
	}
}

func TestCommit_InvalidProjectedRejectedBeforeAnyWrite(t *testing.T) {
	// A plan whose projected config fails validation must be refused before
	// any filesystem mutation. Port 0 is invalid.
	plan := &Plan{projected: &config.Config{}}
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if _, err := Commit(plan, path); err == nil {
		t.Fatal("Commit must reject an invalid projected config")
	}
	// No config and no backup should have been created.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("Commit wrote files for an invalid projection: %v", entries)
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

func TestAtomicReplace_WritesAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := atomicReplace(path, []byte("new content"), 0o640); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new content" {
		t.Fatalf("content = %q, want %q", got, "new content")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", info.Mode().Perm())
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("stray files after atomicReplace: %v", entries)
	}
}
