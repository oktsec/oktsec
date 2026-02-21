package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair("test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Name != "test-agent" {
		t.Errorf("name = %q, want %q", kp.Name, "test-agent")
	}
	if len(kp.PublicKey) != 32 {
		t.Errorf("public key length = %d, want 32", len(kp.PublicKey))
	}
	if len(kp.PrivateKey) != 64 {
		t.Errorf("private key length = %d, want 64", len(kp.PrivateKey))
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	kp, err := GenerateKeypair("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Save(dir); err != nil {
		t.Fatal(err)
	}

	// Check files exist
	if _, err := os.Stat(filepath.Join(dir, "agent-a.key")); err != nil {
		t.Errorf("private key file not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-a.pub")); err != nil {
		t.Errorf("public key file not found: %v", err)
	}

	// Load and compare
	loaded, err := LoadKeypair(dir, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PublicKey.Equal(kp.PublicKey) {
		t.Error("loaded public key doesn't match original")
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, _ := GenerateKeypair("sender")

	from := "sender"
	to := "receiver"
	content := "Hello, this is a test message"
	timestamp := "2026-02-22T10:00:00Z"

	sig := SignMessage(kp.PrivateKey, from, to, content, timestamp)

	result := VerifyMessage(kp.PublicKey, from, to, content, timestamp, sig)
	if !result.Verified {
		t.Errorf("signature should be valid, got error: %v", result.Error)
	}
	if result.Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestVerifyTamperedContent(t *testing.T) {
	kp, _ := GenerateKeypair("sender")

	sig := SignMessage(kp.PrivateKey, "sender", "receiver", "original content", "2026-02-22T10:00:00Z")

	// Tamper with content
	result := VerifyMessage(kp.PublicKey, "sender", "receiver", "tampered content", "2026-02-22T10:00:00Z", sig)
	if result.Verified {
		t.Error("tampered content should not verify")
	}
}

func TestVerifyTamperedSender(t *testing.T) {
	kp, _ := GenerateKeypair("sender")

	sig := SignMessage(kp.PrivateKey, "sender", "receiver", "content", "2026-02-22T10:00:00Z")

	// Tamper with sender
	result := VerifyMessage(kp.PublicKey, "impostor", "receiver", "content", "2026-02-22T10:00:00Z", sig)
	if result.Verified {
		t.Error("tampered sender should not verify")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	kp, _ := GenerateKeypair("sender")

	result := VerifyMessage(kp.PublicKey, "sender", "receiver", "content", "2026-02-22T10:00:00Z", "not-valid-base64!!!")
	if result.Verified {
		t.Error("invalid base64 should not verify")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	kp1, _ := GenerateKeypair("agent-1")
	kp2, _ := GenerateKeypair("agent-2")

	sig := SignMessage(kp1.PrivateKey, "agent-1", "receiver", "content", "2026-02-22T10:00:00Z")

	// Verify with wrong key
	result := VerifyMessage(kp2.PublicKey, "agent-1", "receiver", "content", "2026-02-22T10:00:00Z", sig)
	if result.Verified {
		t.Error("wrong key should not verify")
	}
}

func TestLoadPublicKeys(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"a", "b", "c"} {
		kp, _ := GenerateKeypair(name)
		if err := kp.Save(dir); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := LoadPublicKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Errorf("loaded %d keys, want 3", len(keys))
	}
}

func TestFingerprint(t *testing.T) {
	kp, _ := GenerateKeypair("test")
	fp := Fingerprint(kp.PublicKey)

	if len(fp) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}

	// Same key should give same fingerprint
	fp2 := Fingerprint(kp.PublicKey)
	if fp != fp2 {
		t.Error("fingerprint should be deterministic")
	}
}
