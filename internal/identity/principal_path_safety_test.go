package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests pin the filesystem-containment contract that
// ValidatePrincipalName exists to enforce. They run against the real
// identity package APIs (GenerateKeypair, Save, LoadKeypair,
// LoadPublicKey, LoadPublicKeys) so that future refactors cannot
// silently regress the protection.

func TestGenerateKeypair_RejectsTraversal(t *testing.T) {
	bad := []string{"../escape", "../../etc/passwd", `..\windows`, "a/b", "", "."}
	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			kp, err := GenerateKeypair(name)
			if err == nil {
				t.Fatalf("GenerateKeypair(%q) returned a keypair %+v, want error", name, kp)
			}
		})
	}
}

func TestKeypairSave_RejectsTraversal(t *testing.T) {
	// A Keypair value built directly with an unsafe name must not be
	// allowed to write outside dir.
	dir := t.TempDir()
	kp := &Keypair{Name: "../escape"}
	if err := kp.Save(dir); err == nil {
		t.Fatalf("Keypair{Name: %q}.Save(%q) returned nil, want error", kp.Name, dir)
	}
	// Confirm no file landed in the parent directory.
	parent := filepath.Dir(dir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir %s: %v", parent, err)
	}
	for _, e := range entries {
		if e.Name() == "escape.key" || e.Name() == "escape.pub" {
			t.Fatalf("Save wrote %s into the parent of the keys directory", e.Name())
		}
	}
}

func TestLoadKeypair_RejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	// Plant a benign decoy in the parent that a traversing name would
	// otherwise read. The validator must refuse before the read.
	parent := filepath.Dir(dir)
	decoy := filepath.Join(parent, "decoy.key")
	if err := os.WriteFile(decoy, []byte("not a key"), 0o600); err != nil {
		t.Skipf("could not seed decoy: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(decoy) })

	if _, err := LoadKeypair(dir, "../decoy"); err == nil {
		t.Fatalf("LoadKeypair traversed into parent and succeeded")
	}
	if _, err := LoadPublicKey(dir, "../decoy"); err == nil {
		t.Fatalf("LoadPublicKey traversed into parent and succeeded")
	}
}

func TestLoadPublicKeys_SkipsUnsafeFilenames(t *testing.T) {
	dir := t.TempDir()
	// Plant a .pub file whose stem fails validation, plus a valid one.
	// LoadPublicKeys must skip the invalid entry and return the valid
	// key without erroring out.
	valid := &Keypair{Name: "agent-a"}
	pub, priv, err := generateForTest()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	valid.PublicKey = pub
	valid.PrivateKey = priv
	if err := valid.Save(dir); err != nil {
		t.Fatalf("save valid: %v", err)
	}
	// A filename whose stem starts with "." fails validation. Seed it
	// directly so we don't try to construct an invalid Keypair through
	// the validated API.
	unsafe := filepath.Join(dir, ".hidden.pub")
	if err := os.WriteFile(unsafe, []byte("ignored"), 0o644); err != nil {
		t.Fatalf("seed unsafe pub: %v", err)
	}

	keys, err := LoadPublicKeys(dir)
	if err != nil {
		t.Fatalf("LoadPublicKeys returned error %v, want nil with skip behavior", err)
	}
	if _, ok := keys["agent-a"]; !ok {
		t.Fatalf("LoadPublicKeys lost the valid agent-a key: %v", keys)
	}
	if _, ok := keys[".hidden"]; ok {
		t.Fatalf("LoadPublicKeys returned an unsafe filename as a key entry")
	}
}

// generateForTest is a local helper that mirrors GenerateKeypair without
// the principal-name check, so tests can seed files with arbitrary key
// material when needed. We never expose this from the package itself.
func generateForTest() (pub []byte, priv []byte, err error) {
	tmp, err := GenerateKeypair("seed")
	if err != nil {
		return nil, nil, err
	}
	return tmp.PublicKey, tmp.PrivateKey, nil
}
