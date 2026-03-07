package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// ComputeEntryHash computes a SHA-256 hash over the chain-relevant fields of an
// audit entry. The hash covers the previous hash, entry ID, timestamp, agents,
// content hash, and status to form a tamper-evident chain.
func ComputeEntryHash(prevHash, id, ts, from, to, contentHash, status string) string {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s", prevHash, id, ts, from, to, contentHash, status)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// SignEntryHash signs an entry hash with the proxy's Ed25519 private key.
func SignEntryHash(key ed25519.PrivateKey, entryHash string) string {
	sig := ed25519.Sign(key, []byte(entryHash))
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifyEntrySignature verifies an entry hash signature against the proxy's public key.
func VerifyEntrySignature(pub ed25519.PublicKey, entryHash, signature string) bool {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(entryHash), sig)
}

// ChainVerifyResult holds the result of verifying an audit chain.
type ChainVerifyResult struct {
	Valid      bool   `json:"valid"`
	Entries    int    `json:"entries"`
	BrokenAt   int    `json:"broken_at,omitempty"`  // index of first broken link (-1 if valid)
	BrokenID   string `json:"broken_id,omitempty"`  // ID of the broken entry
	Reason     string `json:"reason,omitempty"`
}

// VerifyChain validates the hash chain and signatures of a sequence of audit entries.
// Entries must be ordered oldest-first (ascending timestamp).
func VerifyChain(entries []ChainEntry, proxyPub ed25519.PublicKey) ChainVerifyResult {
	if len(entries) == 0 {
		return ChainVerifyResult{Valid: true, Entries: 0, BrokenAt: -1}
	}

	for i, e := range entries {
		// Recompute hash
		expectedHash := ComputeEntryHash(e.PrevHash, e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.ContentHash, e.Status)
		if e.EntryHash != expectedHash {
			return ChainVerifyResult{
				Valid:    false,
				Entries:  len(entries),
				BrokenAt: i,
				BrokenID: e.ID,
				Reason:   "entry hash mismatch",
			}
		}

		// Verify chain link (except first entry)
		if i > 0 && e.PrevHash != entries[i-1].EntryHash {
			return ChainVerifyResult{
				Valid:    false,
				Entries:  len(entries),
				BrokenAt: i,
				BrokenID: e.ID,
				Reason:   "chain link broken — prev_hash does not match previous entry",
			}
		}

		// Verify signature if proxy key provided
		if proxyPub != nil && e.ProxySignature != "" {
			if !VerifyEntrySignature(proxyPub, e.EntryHash, e.ProxySignature) {
				return ChainVerifyResult{
					Valid:    false,
					Entries:  len(entries),
					BrokenAt: i,
					BrokenID: e.ID,
					Reason:   "proxy signature invalid",
				}
			}
		}
	}

	return ChainVerifyResult{Valid: true, Entries: len(entries), BrokenAt: -1}
}

// ChainEntry extends Entry with chain fields for verification purposes.
type ChainEntry struct {
	Entry
	PrevHash       string `json:"prev_hash"`
	EntryHash      string `json:"entry_hash"`
	ProxySignature string `json:"proxy_signature"`
}
