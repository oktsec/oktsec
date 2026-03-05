package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyStore_GetNotFound(t *testing.T) {
	ks := NewKeyStore()
	_, ok := ks.Get("nonexistent")
	if ok {
		t.Error("Get for missing key should return false")
	}
}

func TestKeyStore_LoadAndGet(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeypair("agent-x")
	if err := kp.Save(dir); err != nil {
		t.Fatal(err)
	}

	ks := NewKeyStore()
	if err := ks.LoadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	key, ok := ks.Get("agent-x")
	if !ok {
		t.Fatal("agent-x key not found")
	}
	if !key.Equal(kp.PublicKey) {
		t.Error("loaded key doesn't match original")
	}
}

func TestKeyStore_Count(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		kp, _ := GenerateKeypair(name)
		if err := kp.Save(dir); err != nil {
			t.Fatal(err)
		}
	}

	ks := NewKeyStore()
	if err := ks.LoadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	if got := ks.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}
}

func TestKeyStore_Names(t *testing.T) {
	dir := t.TempDir()
	expected := []string{"alpha", "beta"}
	for _, name := range expected {
		kp, _ := GenerateKeypair(name)
		if err := kp.Save(dir); err != nil {
			t.Fatal(err)
		}
	}

	ks := NewKeyStore()
	if err := ks.LoadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	names := ks.Names()
	if len(names) != 2 {
		t.Fatalf("Names count = %d, want 2", len(names))
	}

	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	for _, exp := range expected {
		if !nameSet[exp] {
			t.Errorf("missing name %q", exp)
		}
	}
}

func TestKeyStore_ReloadFromDir(t *testing.T) {
	dir := t.TempDir()
	kp1, _ := GenerateKeypair("first")
	if err := kp1.Save(dir); err != nil {
		t.Fatal(err)
	}

	ks := NewKeyStore()
	if err := ks.LoadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	if ks.Count() != 1 {
		t.Fatalf("initial count = %d, want 1", ks.Count())
	}

	// Add a second key and reload
	kp2, _ := GenerateKeypair("second")
	if err := kp2.Save(dir); err != nil {
		t.Fatal(err)
	}

	if err := ks.ReloadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	if ks.Count() != 2 {
		t.Errorf("after reload count = %d, want 2", ks.Count())
	}
}

func TestKeyStore_ReloadReplacesKeys(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeypair("agent")
	if err := kp.Save(dir); err != nil {
		t.Fatal(err)
	}

	ks := NewKeyStore()
	if err := ks.LoadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	// Remove the key file and reload
	_ = os.Remove(filepath.Join(dir, "agent.pub"))
	_ = os.Remove(filepath.Join(dir, "agent.key"))

	if err := ks.ReloadFromDir(dir); err != nil {
		t.Fatal(err)
	}

	if ks.Count() != 0 {
		t.Errorf("after reload with no keys, count = %d, want 0", ks.Count())
	}
}

func TestKeyStore_LoadFromDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeyStore()
	if err := ks.LoadFromDir(dir); err != nil {
		t.Fatal(err)
	}
	if ks.Count() != 0 {
		t.Error("empty dir should yield 0 keys")
	}
}

func TestKeyStore_LoadFromDir_InvalidDir(t *testing.T) {
	ks := NewKeyStore()
	err := ks.LoadFromDir("/nonexistent/path/to/keys")
	if err == nil {
		t.Error("loading from nonexistent dir should fail")
	}
}

func TestLoadKeypair_DerivePublicFromPrivate(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeypair("test")
	if err := kp.Save(dir); err != nil {
		t.Fatal(err)
	}

	// Remove the public key file to test derivation from private
	_ = os.Remove(filepath.Join(dir, "test.pub"))

	loaded, err := LoadKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PublicKey.Equal(kp.PublicKey) {
		t.Error("derived public key should match original")
	}
}

func TestLoadPublicKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "bad.pub"), []byte("not a PEM file"), 0o644)

	_, err := LoadPublicKey(dir, "bad")
	if err == nil {
		t.Error("invalid PEM should fail")
	}
}

func TestLoadKeypair_InvalidPrivateKey(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "bad.key"), []byte("not a PEM file"), 0o644)

	_, err := LoadKeypair(dir, "bad")
	if err == nil {
		t.Error("invalid private key PEM should fail")
	}
}

func TestVerifyMessage_EmptySignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	result := VerifyMessage(pub, "a", "b", "c", "t", "")
	if result.Verified {
		t.Error("empty signature should not verify")
	}
}

func TestCanonicalPayload_Deterministic(t *testing.T) {
	p1 := canonicalPayload("a", "b", "c", "d")
	p2 := canonicalPayload("a", "b", "c", "d")
	if string(p1) != string(p2) {
		t.Error("canonical payload should be deterministic")
	}
}

func TestCanonicalPayload_DifferentInputs(t *testing.T) {
	p1 := canonicalPayload("a", "b", "c", "d")
	p2 := canonicalPayload("x", "y", "z", "w")
	if string(p1) == string(p2) {
		t.Error("different inputs should produce different payloads")
	}
}

func TestSignMessage_ProducesNonEmpty(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignMessage(priv, "from", "to", "content", "ts")
	if sig == "" {
		t.Error("SignMessage should produce non-empty signature")
	}
}

func TestVerifyResult_IncludesFingerprint(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignMessage(priv, "f", "t", "c", "ts")
	result := VerifyMessage(pub, "f", "t", "c", "ts", sig)
	if result.Fingerprint == "" {
		t.Error("VerifyResult should include fingerprint on success")
	}
}

func TestVerifyResult_IncludesFingerprintOnFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignMessage(priv2, "f", "t", "c", "ts")

	result := VerifyMessage(pub, "f", "t", "c", "ts", sig)
	if result.Verified {
		t.Error("wrong key should not verify")
	}
	if result.Fingerprint == "" {
		t.Error("fingerprint should be set even on verification failure")
	}
}
