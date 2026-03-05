package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultDBPath(t *testing.T) {
	path := defaultDBPath()

	if path == "" {
		t.Fatal("defaultDBPath returned empty string")
	}

	// Should end with oktsec.db
	if !strings.HasSuffix(path, "oktsec.db") {
		t.Errorf("path %q should end with oktsec.db", path)
	}

	// Should be absolute
	if !filepath.IsAbs(path) {
		t.Errorf("path %q should be absolute", path)
	}

	// Parent directory should exist (defaultDBPath creates it)
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		t.Errorf("parent dir %q should exist: %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("%q should be a directory", dir)
	}

	// On non-Windows, should be under ~/.oktsec/
	if runtime.GOOS != "windows" {
		home, _ := os.UserHomeDir()
		expected := filepath.Join(home, ".oktsec")
		if !strings.HasPrefix(path, expected) {
			t.Errorf("path %q should be under %q", path, expected)
		}
	}
}

func TestDefaultDBPath_Idempotent(t *testing.T) {
	path1 := defaultDBPath()
	path2 := defaultDBPath()

	if path1 != path2 {
		t.Errorf("defaultDBPath not idempotent: %q != %q", path1, path2)
	}
}

func TestDefaultDBPath_DirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission check not reliable on Windows")
	}

	path := defaultDBPath()
	dir := filepath.Dir(path)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	perm := info.Mode().Perm()
	if perm != 0o700 {
		t.Errorf("dir permissions = %o, want 700", perm)
	}
}

func TestSetupCmd_Help(t *testing.T) {
	cmd := newSetupCmd()

	if cmd.Use != "setup" {
		t.Errorf("Use = %q, want setup", cmd.Use)
	}

	// Verify flags exist
	flags := []string{"keys", "config", "enforce", "skip-wrap"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing flag: %s", name)
		}
	}
}

func TestSetupCmd_FlagDefaults(t *testing.T) {
	cmd := newSetupCmd()

	keysFlag := cmd.Flags().Lookup("keys")
	if keysFlag.DefValue != "./keys" {
		t.Errorf("keys default = %q, want ./keys", keysFlag.DefValue)
	}

	configFlag := cmd.Flags().Lookup("config")
	if configFlag.DefValue != "oktsec.yaml" {
		t.Errorf("config default = %q, want oktsec.yaml", configFlag.DefValue)
	}

	enforceFlag := cmd.Flags().Lookup("enforce")
	if enforceFlag.DefValue != "false" {
		t.Errorf("enforce default = %q, want false", enforceFlag.DefValue)
	}

	skipWrapFlag := cmd.Flags().Lookup("skip-wrap")
	if skipWrapFlag.DefValue != "false" {
		t.Errorf("skip-wrap default = %q, want false", skipWrapFlag.DefValue)
	}
}

func TestWrapCmd_RequiresClientOrAll(t *testing.T) {
	cmd := newWrapCmd()
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Error("wrap with no args and no --all should fail")
	}
	if !strings.Contains(err.Error(), "specify a client name or use --all") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWrapCmd_AllAndClientMutuallyExclusive(t *testing.T) {
	cmd := newWrapCmd()
	cmd.SetArgs([]string{"--all", "cursor"})

	err := cmd.Execute()
	if err == nil {
		t.Error("wrap with --all and a client should fail")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWrapCmd_Flags(t *testing.T) {
	cmd := newWrapCmd()

	flags := []string{"enforce", "all"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing flag: %s", name)
		}
	}
}
