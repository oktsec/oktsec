package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestComputeEntryHash_Deterministic(t *testing.T) {
	h1 := ComputeEntryHash("prev", "id1", "2026-01-01T00:00:00Z", "a", "b", "abc123", "delivered")
	h2 := ComputeEntryHash("prev", "id1", "2026-01-01T00:00:00Z", "a", "b", "abc123", "delivered")
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 { // SHA-256 hex
		t.Fatalf("unexpected hash length: %d", len(h1))
	}
}

func TestComputeEntryHash_DifferentInputs(t *testing.T) {
	h1 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "delivered")
	h2 := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "hash1", "blocked")
	if h1 == h2 {
		t.Fatal("different statuses should produce different hashes")
	}
}

func TestSignAndVerifyEntryHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hash := ComputeEntryHash("", "id1", "2026-01-01T00:00:00Z", "a", "b", "abc", "delivered")
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

func TestVerifyChain_ValidChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Build a 3-entry chain
	entries := make([]ChainEntry, 3)
	prevHash := ""
	for i := 0; i < 3; i++ {
		e := ChainEntry{
			Entry: Entry{
				ID:          fmt.Sprintf("id-%d", i),
				Timestamp:   "2026-01-01T00:00:00Z",
				FromAgent:   "a",
				ToAgent:     "b",
				ContentHash: fmt.Sprintf("content-%d", i),
				Status:      "delivered",
			},
			PrevHash: prevHash,
		}
		e.EntryHash = ComputeEntryHash(e.PrevHash, e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.ContentHash, e.Status)
		e.ProxySignature = SignEntryHash(priv, e.EntryHash)
		entries[i] = e
		prevHash = e.EntryHash
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
		e := ChainEntry{
			Entry: Entry{
				ID:          fmt.Sprintf("id-%d", i),
				Timestamp:   "2026-01-01T00:00:00Z",
				FromAgent:   "a",
				ToAgent:     "b",
				ContentHash: fmt.Sprintf("content-%d", i),
				Status:      "delivered",
			},
			PrevHash: prevHash,
		}
		e.EntryHash = ComputeEntryHash(e.PrevHash, e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.ContentHash, e.Status)
		e.ProxySignature = SignEntryHash(priv, e.EntryHash)
		entries[i] = e
		prevHash = e.EntryHash
	}

	// Tamper with middle entry's status
	entries[1].Status = "blocked"

	result := VerifyChain(entries, pub)
	if result.Valid {
		t.Fatal("tampered chain should be invalid")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("expected break at index 1, got %d", result.BrokenAt)
	}
}

func TestVerifyChain_BrokenLink(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	entries := make([]ChainEntry, 2)
	// First entry
	entries[0] = ChainEntry{
		Entry: Entry{
			ID: "id-0", Timestamp: "2026-01-01T00:00:00Z",
			FromAgent: "a", ToAgent: "b", ContentHash: "c0", Status: "delivered",
		},
		PrevHash: "",
	}
	entries[0].EntryHash = ComputeEntryHash("", "id-0", "2026-01-01T00:00:00Z", "a", "b", "c0", "delivered")
	entries[0].ProxySignature = SignEntryHash(priv, entries[0].EntryHash)

	// Second entry with wrong prev_hash
	entries[1] = ChainEntry{
		Entry: Entry{
			ID: "id-1", Timestamp: "2026-01-01T00:00:01Z",
			FromAgent: "a", ToAgent: "b", ContentHash: "c1", Status: "delivered",
		},
		PrevHash: "wrong-prev-hash",
	}
	entries[1].EntryHash = ComputeEntryHash("wrong-prev-hash", "id-1", "2026-01-01T00:00:01Z", "a", "b", "c1", "delivered")
	entries[1].ProxySignature = SignEntryHash(priv, entries[1].EntryHash)

	result := VerifyChain(entries, nil) // skip sig verification
	if result.Valid {
		t.Fatal("broken chain link should be invalid")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("expected break at index 1, got %d", result.BrokenAt)
	}
}
