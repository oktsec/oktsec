package sdk

import (
	"os"
	"path/filepath"
	"testing"
)

// LoadKeypair must refuse a traversal name before it tries to read
// outside dir. We seed a benign decoy in the parent directory so a
// regression that drops the validation would succeed silently.
func TestLoadKeypair_RejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Dir(dir)

	decoyKey := filepath.Join(parent, "decoy.key")
	if err := os.WriteFile(decoyKey, []byte("not a key"), 0o600); err != nil {
		t.Skipf("could not seed decoy: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(decoyKey) })

	if _, err := LoadKeypair(dir, "../decoy"); err == nil {
		t.Fatal("LoadKeypair followed a traversal name and returned a keypair")
	}
	if _, err := LoadKeypair(dir, "a/b"); err == nil {
		t.Fatal("LoadKeypair accepted a path-separator name")
	}
	if _, err := LoadKeypair(dir, ""); err == nil {
		t.Fatal("LoadKeypair accepted an empty name")
	}
}
