package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// TestDefaultDBPath_PrefersConfig locks in the fix for the CLI/server
// mismatch: before unifying, defaultDBPath() returned ~/.oktsec/oktsec.db
// unconditionally while the running server followed cfg.DBPath from
// oktsec.yaml. Operators saw different CRLs / quarantine queues depending
// on which tool they reached for. This test fails if anyone ever lets
// defaultDBPath() drift back to config.DefaultDBPath() directly.
func TestDefaultDBPath_PrefersConfig(t *testing.T) {
	dir := t.TempDir()
	wantPath := filepath.Join(dir, "custom-audit.db")
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	cfg := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: dir},
		DBPath:   wantPath,
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	orig := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = orig })

	got := defaultDBPath()
	if got != wantPath {
		t.Fatalf("defaultDBPath() = %q, want %q (config-driven path)", got, wantPath)
	}
}

// When the config can't be loaded (missing, malformed) or has no db_path
// we want a sane default rather than an empty string. That behaviour is
// shared with the previous resolveDBPath() implementation — kept tested
// so the fallback isn't silently dropped during future refactors.
func TestDefaultDBPath_FallsBackToDefaultWhenNoConfig(t *testing.T) {
	orig := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")
	t.Cleanup(func() { cfgFile = orig })

	got := defaultDBPath()
	if got == "" {
		t.Fatal("fallback must not be empty — callers open sql.DB with this path")
	}
	if _, err := os.Stat(filepath.Dir(got)); err != nil && !os.IsNotExist(err) {
		t.Fatalf("default dir should be resolvable: %v", err)
	}
}
