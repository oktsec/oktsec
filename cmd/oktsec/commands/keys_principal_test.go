package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

// keygen must refuse a path-traversal agent name before any file lands
// on disk. The check sits on identity.GenerateKeypair, but this test
// drives the CLI command end to end so a future refactor that moves
// the call site cannot regress the protection.
func TestKeygen_RejectsTraversalAgent(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := newKeygenCmd()
	cmd.SetArgs([]string{"--agent=../../pwn", "--out=" + outDir})
	if err := cmd.Execute(); err == nil {
		t.Fatal("keygen accepted a traversal agent name")
	}

	parent := filepath.Dir(outDir)
	for _, leaf := range []string{"pwn.key", "pwn.pub"} {
		if _, err := os.Stat(filepath.Join(parent, leaf)); err == nil {
			t.Fatalf("keygen wrote %s outside the keys directory", leaf)
		}
	}
}

// keys rotate must refuse the same shape and must not touch the
// keys dir (no rename, no new keypair). We seed a valid alice keypair,
// run rotate with a traversal name, then assert alice's files are
// untouched.
func TestKeysRotate_RejectsTraversalAgent(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Seed an existing keypair the traversal name must not be able to
	// rename or replace.
	kp, err := identity.GenerateKeypair("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Save(keysDir); err != nil {
		t.Fatal(err)
	}
	aliceKeyBefore, err := os.ReadFile(filepath.Join(keysDir, "alice.key"))
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "oktsec.yaml")
	seed := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Agents: map[string]config.Agent{
			"alice": {CanMessage: []string{"*"}, KeyVersion: 1},
		},
		DBPath: filepath.Join(dir, "oktsec.db"),
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	origCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = origCfgFile })

	cmd := newKeysCmd()
	cmd.SetArgs([]string{"rotate", "--agent=../../pwn"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("keys rotate accepted a traversal agent name")
	}

	// Confirm no files landed outside the keys dir.
	parent := filepath.Dir(keysDir)
	for _, leaf := range []string{"pwn.key", "pwn.pub"} {
		if _, err := os.Stat(filepath.Join(parent, leaf)); err == nil {
			t.Fatalf("rotate created %s outside the keys directory", leaf)
		}
	}

	// Confirm alice's private key bytes are unchanged.
	aliceKeyAfter, err := os.ReadFile(filepath.Join(keysDir, "alice.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(aliceKeyBefore) != string(aliceKeyAfter) {
		t.Fatal("alice's keypair was modified during a rejected rotation")
	}
}
