package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestComputeEntryHash_Deterministic(t *testing.T) {
	h1 := ComputeEntryHash("prev", "id1", "2026-01-01T00:00:00Z", "a", "b", "abc123", "delivered", "clean", "[]", 1)
	h2 := ComputeEntryHash("prev", "id1", "2026-01-01T00:00:00Z", "a", "b", "abc123", "delivered", "clean", "[]", 1)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 { // SHA-256 hex
		t.Fatalf("unexpected hash length: %d", len(h1))
	}
}

func TestComputeEntryHash_DifferentInputs(t *testing.T) {
	h1 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "delivered", "clean", "[]", 1)
	h2 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "blocked", "clean", "[]", 1)
	if h1 == h2 {
		t.Fatal("different statuses should produce different hashes")
	}
}

func TestComputeEntryHash_PolicyDecisionChangesHash(t *testing.T) {
	h1 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "blocked", "clean", "[]", 1)
	h2 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "blocked", "acl_denied", "[]", 1)
	if h1 == h2 {
		t.Fatal("different policy decisions must produce different hashes (v2 guarantee)")
	}
}

func TestComputeEntryHash_RulesTriggeredChangesHash(t *testing.T) {
	h1 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "blocked", "clean", `[]`, 1)
	h2 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "blocked", "clean", `[{"rule_id":"IAP-001"}]`, 1)
	if h1 == h2 {
		t.Fatal("different rules_triggered must produce different hashes (v2 guarantee)")
	}
}

func TestSignAndVerifyEntryHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hash := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "abc", "delivered", "clean", "[]", 1)
	sig := SignEntryHash(priv, hash)

	if !VerifyEntrySignature(pub, hash, sig) {
		t.Fatal("valid signature rejected")
	}

	// Tampered hash
	if VerifyEntrySignature(pub, hash+"x", sig) {
		t.Fatal("tampered hash should fail verification")
	}

	// Invalid base64
	if VerifyEntrySignature(pub, hash, "not-base64!!!") {
		t.Fatal("invalid base64 should fail")
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	result := VerifyChain(nil, nil)
	if !result.Valid {
		t.Fatal("empty chain should be valid")
	}
}

func buildChainEntry(i int, prevHash string, priv ed25519.PrivateKey) ChainEntry {
	e := ChainEntry{
		Entry: Entry{
			ID:                fmt.Sprintf("id-%d", i),
			Timestamp:         "2026-01-01T00:00:00Z",
			FromAgent:         "a",
			ToAgent:           "b",
			ContentHash:       fmt.Sprintf("content-%d", i),
			Status:            "delivered",
			PolicyDecision:    "clean",
			RulesTriggered:    "[]",
			SignatureVerified: 1,
		},
		PrevHash: prevHash,
	}
	e.EntryHash = ComputeEntryHash(e.PrevHash, e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.ContentHash, e.Status, e.PolicyDecision, e.RulesTriggered, e.SignatureVerified)
	e.ProxySignature = SignEntryHash(priv, e.EntryHash)
	return e
}

func TestVerifyChain_ValidChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	entries := make([]ChainEntry, 3)
	prevHash := ""
	for i := 0; i < 3; i++ {
		entries[i] = buildChainEntry(i, prevHash, priv)
		prevHash = entries[i].EntryHash
	}

	result := VerifyChain(entries, pub)
	if !result.Valid {
		t.Fatalf("valid chain rejected: %s", result.Reason)
	}
	if result.Entries != 3 {
		t.Fatalf("expected 3 entries, got %d", result.Entries)
	}
}

func TestVerifyChain_TamperedEntry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	entries := make([]ChainEntry, 3)
	prevHash := ""
	for i := 0; i < 3; i++ {
		entries[i] = buildChainEntry(i, prevHash, priv)
		prevHash = entries[i].EntryHash
	}

	entries[1].Status = "blocked"

	result := VerifyChain(entries, pub)
	if result.Valid {
		t.Fatal("tampered chain should be invalid")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("expected break at index 1, got %d", result.BrokenAt)
	}
}

// v2 guarantee: mutating policy_decision or rules_triggered must invalidate the chain.
func TestVerifyChain_DetectsPolicyDecisionTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	entries := make([]ChainEntry, 2)
	prevHash := ""
	for i := 0; i < 2; i++ {
		entries[i] = buildChainEntry(i, prevHash, priv)
		prevHash = entries[i].EntryHash
	}

	// Attacker flips a blocked decision to clean without recomputing the hash.
	entries[1].PolicyDecision = "acl_denied"

	result := VerifyChain(entries, nil)
	if result.Valid {
		t.Fatal("policy_decision mutation must break the chain")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("expected break at index 1, got %d", result.BrokenAt)
	}
}

func TestVerifyChain_DetectsRulesTriggeredTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	entries := make([]ChainEntry, 2)
	prevHash := ""
	for i := 0; i < 2; i++ {
		entries[i] = buildChainEntry(i, prevHash, priv)
		prevHash = entries[i].EntryHash
	}

	entries[0].RulesTriggered = `[{"rule_id":"ghost-rule"}]`

	result := VerifyChain(entries, nil)
	if result.Valid {
		t.Fatal("rules_triggered mutation must break the chain")
	}
	if result.BrokenAt != 0 {
		t.Fatalf("expected break at index 0, got %d", result.BrokenAt)
	}
}

// Backwards-compat: a chain signed with v1 hashes must still verify, because
// operators upgrading to v0.15.0 may have audit logs written under v1.
func TestVerifyChain_AcceptsLegacyV1Hash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	entries := make([]ChainEntry, 2)
	prevHash := ""
	for i := 0; i < 2; i++ {
		e := ChainEntry{
			Entry: Entry{
				ID: fmt.Sprintf("id-%d", i), Timestamp: "2026-01-01T00:00:00Z",
				FromAgent: "a", ToAgent: "b",
				ContentHash: fmt.Sprintf("c-%d", i), Status: "delivered",
			},
			PrevHash: prevHash,
		}
		e.EntryHash = computeEntryHashV1(e.PrevHash, e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.ContentHash, e.Status)
		e.ProxySignature = SignEntryHash(priv, e.EntryHash)
		entries[i] = e
		prevHash = e.EntryHash
	}

	result := VerifyChain(entries, nil)
	if !result.Valid {
		t.Fatalf("legacy v1 chain must still verify: %s", result.Reason)
	}
}

func TestVerifyChain_BrokenLink(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	entries := make([]ChainEntry, 2)
	entries[0] = buildChainEntry(0, "", priv)

	entries[1] = buildChainEntry(1, "wrong-prev-hash", priv)

	result := VerifyChain(entries, nil)
	if result.Valid {
		t.Fatal("broken chain link should be invalid")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("expected break at index 1, got %d", result.BrokenAt)
	}
}
