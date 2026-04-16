package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerifyV2_HappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := SignMessageV2(priv, "alice", "bob", "hi", "2026-04-01T00:00:00Z", 3)
	r := VerifyMessageV2(pub, "alice", "bob", "hi", "2026-04-01T00:00:00Z", 3, sig)
	if !r.Verified {
		t.Fatalf("V2 signature should verify: %v", r.Error)
	}
}

// A v1 signature must NOT verify under a v2 check — otherwise an attacker
// who captures a v1 signature can replay it after a key rotation and claim
// it was signed with the new version.
func TestV1SignatureRejectedByV2Verify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v1Sig := SignMessage(priv, "alice", "bob", "hi", "2026-04-01T00:00:00Z")
	r := VerifyMessageV2(pub, "alice", "bob", "hi", "2026-04-01T00:00:00Z", 1, v1Sig)
	if r.Verified {
		t.Fatal("v1 signature must not verify under v2 check")
	}
}

// Flipping the version on a V2 signature must break verification — this is
// the whole point of binding the signature to the key version.
func TestV2Signature_VersionMismatchRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignMessageV2(priv, "alice", "bob", "hi", "2026-04-01T00:00:00Z", 2)
	r := VerifyMessageV2(pub, "alice", "bob", "hi", "2026-04-01T00:00:00Z", 3, sig)
	if r.Verified {
		t.Fatal("signature should not verify when claimed version differs from signed version")
	}
}

// Sanity: v1 verification path still works on v1 signatures so legacy SDKs
// keep functioning during the rollout.
func TestV1Signature_V1VerifyStillWorks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignMessage(priv, "alice", "bob", "hi", "2026-04-01T00:00:00Z")
	r := VerifyMessage(pub, "alice", "bob", "hi", "2026-04-01T00:00:00Z", sig)
	if !r.Verified {
		t.Fatal("v1 signature must still verify under v1 path")
	}
}
