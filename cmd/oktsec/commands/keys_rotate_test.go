package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

// TestKeysRotate_BumpsKeyVersion is the regression test for the v0.15.1
// follow-up: rotating a key must increment Agent.KeyVersion in oktsec.yaml,
// otherwise a captured v1 signature from the old key can still be replayed
// because the proxy has no version pin to compare against.
//
// We drive the command directly instead of shelling out — the cobra command
// is declared in keys.go, so we can Execute() it with flags wired in.
func TestKeysRotate_BumpsKeyVersion(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Seed an initial keypair + config.
	kp, err := identity.GenerateKeypair("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Save(keysDir); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "oktsec.yaml")
	seed := &config.Config{
		Version: "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Agents: map[string]config.Agent{
			"alice": {CanMessage: []string{"*"}, KeyVersion: 3},
		},
		DBPath: filepath.Join(dir, "oktsec.db"),
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	// Point the shared cfgFile at our fixture for the duration of this test.
	origCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = origCfgFile })

	cmd := newKeysCmd()
	cmd.SetArgs([]string{"rotate", "--agent=alice"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rotate failed: %v", err)
	}

	after, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got := after.Agents["alice"].KeyVersion
	if got != 4 {
		t.Fatalf("expected KeyVersion 3 -> 4, got %d", got)
	}

	// The old keypair should be in revoked/, not at the original path.
	if _, err := os.Stat(filepath.Join(keysDir, "revoked", "alice.pub")); err != nil {
		t.Fatalf("old public key should be moved to revoked/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(keysDir, "alice.pub")); err != nil {
		t.Fatalf("new public key should exist at keys dir: %v", err)
	}

	// Fingerprint must be different from the seed — proves we wrote a new key,
	// not moved the old one back.
	newPub, err := identity.LoadPublicKey(keysDir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Fingerprint(newPub) == identity.Fingerprint(kp.PublicKey) {
		t.Fatal("rotated key has same fingerprint as original — nothing actually rotated")
	}
}

// If the agent config had no key_version (0, the legacy default), the
// rotate command should seed it to 1 rather than leaving it at 0, otherwise
// the rotation still lets v1 signatures verify.
func TestKeysRotate_SeedsKeyVersionFromZero(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	_ = os.MkdirAll(keysDir, 0o700)

	kp, _ := identity.GenerateKeypair("bob")
	_ = kp.Save(keysDir)

	cfgPath := filepath.Join(dir, "oktsec.yaml")
	seed := &config.Config{
		Version: "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Agents: map[string]config.Agent{
			"bob": {CanMessage: []string{"*"}}, // KeyVersion omitted -> 0
		},
		DBPath: filepath.Join(dir, "oktsec.db"),
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	orig := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = orig })

	cmd := newKeysCmd()
	cmd.SetArgs([]string{"rotate", "--agent=bob"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rotate failed: %v", err)
	}

	after, _ := config.Load(cfgPath)
	if got := after.Agents["bob"].KeyVersion; got != 1 {
		t.Fatalf("expected KeyVersion 0 -> 1, got %d", got)
	}
}

func init() {
	// Ensure test binaries that import this package don't carry a stale
	// cfgFile between packages.
	if strings.Contains(os.Args[0], ".test") {
		cfgFile = ""
	}
}
