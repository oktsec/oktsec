package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DelegationToken represents a cryptographically signed authorization from one
// agent (delegator) to another (delegate), granting scoped messaging permissions.
//
// Tokens can be chained: Human -> Agent A -> Agent B -> Agent C. Each hop
// narrows scope and carries a reference to the parent token, creating a
// cryptographically verifiable chain back to the original human authorization.
type DelegationToken struct {
	Delegator string    `json:"delegator"`           // parent agent name
	Delegate  string    `json:"delegate"`            // child agent name
	Scope     []string  `json:"scope"`               // allowed recipients, or ["*"] for all
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature,omitempty"` // base64(ed25519 sig by delegator)

	// Chain fields — enable multi-hop delegation with cryptographic binding.
	TokenID       string   `json:"token_id,omitempty"`        // SHA-256 of canonical payload (computed on create)
	ParentTokenID string   `json:"parent_token_id,omitempty"` // TokenID of the parent delegation (empty for root)
	ChainDepth    int      `json:"chain_depth"`               // 0 = human/root, 1 = first agent hop, etc.
	MaxDepth      int      `json:"max_depth"`                 // maximum allowed re-delegation depth
	AllowedTools  []string `json:"allowed_tools,omitempty"`   // tool scope narrows per hop (nil = all tools)
}

// DelegationChain is an ordered list of tokens forming a delegation path
// from a root authorizer (typically human) to the current agent.
// Tokens are ordered oldest-first: chain[0] is the root delegation.
type DelegationChain []DelegationToken

// delegationPayload builds the canonical byte payload for signing/verification.
// Includes chain fields so they can't be tampered with after signing.
func delegationPayload(t *DelegationToken) []byte {
	scopeCSV := strings.Join(t.Scope, ",")
	toolsCSV := strings.Join(t.AllowedTools, ",")
	s := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%s",
		t.Delegator, t.Delegate, scopeCSV,
		t.IssuedAt.UTC().Format(time.RFC3339),
		t.ExpiresAt.UTC().Format(time.RFC3339),
		t.ParentTokenID,
		t.ChainDepth, t.MaxDepth,
		toolsCSV,
	)
	return []byte(s)
}

// legacyPayload preserves the original 5-field format for backward
// compatibility with tokens created before chain support.
func legacyPayload(delegator, delegate string, scope []string, issuedAt, expiresAt time.Time) []byte {
	scopeCSV := strings.Join(scope, ",")
	s := fmt.Sprintf("%s\n%s\n%s\n%s\n%s",
		delegator, delegate, scopeCSV,
		issuedAt.UTC().Format(time.RFC3339),
		expiresAt.UTC().Format(time.RFC3339),
	)
	return []byte(s)
}

// computeTokenID returns the SHA-256 hex digest of the canonical payload.
func computeTokenID(t *DelegationToken) string {
	h := sha256.Sum256(delegationPayload(t))
	return hex.EncodeToString(h[:])
}

// CreateDelegation creates a signed delegation token from delegator to delegate.
// The delegator's private key signs the canonical payload.
// For backward compatibility, creates a depth-0, max-depth-0 token (no chaining).
func CreateDelegation(delegatorKey ed25519.PrivateKey, delegator, delegate string, scope []string, ttl time.Duration) *DelegationToken {
	return CreateChainedDelegation(delegatorKey, delegator, delegate, scope, nil, ttl, "", 0, 3)
}

// CreateChainedDelegation creates a delegation token that is part of a chain.
// parentTokenID links to the parent delegation (empty for root/human).
// chainDepth is this token's position (0 for root). maxDepth caps re-delegation.
// allowedTools restricts which tools the delegate can use (nil = all).
func CreateChainedDelegation(
	delegatorKey ed25519.PrivateKey,
	delegator, delegate string,
	scope, allowedTools []string,
	ttl time.Duration,
	parentTokenID string,
	chainDepth, maxDepth int,
) *DelegationToken {
	now := time.Now().UTC()
	token := &DelegationToken{
		Delegator:     delegator,
		Delegate:      delegate,
		Scope:         scope,
		IssuedAt:      now,
		ExpiresAt:     now.Add(ttl),
		ParentTokenID: parentTokenID,
		ChainDepth:    chainDepth,
		MaxDepth:      maxDepth,
		AllowedTools:  allowedTools,
	}

	// Compute token ID from unsigned payload
	token.TokenID = computeTokenID(token)

	// Sign the canonical payload (includes all chain fields)
	payload := delegationPayload(token)
	sig := ed25519.Sign(delegatorKey, payload)
	token.Signature = base64.StdEncoding.EncodeToString(sig)

	return token
}

// DelegationVerifyResult holds the outcome of delegation verification.
type DelegationVerifyResult struct {
	Valid  bool
	Reason string
}

// ChainVerifyResult holds the outcome of a full chain verification.
type ChainVerifyResult struct {
	Valid      bool
	Reason     string
	Depth      int      // total chain depth
	Root       string   // root delegator (human/origin)
	Delegate   string   // final delegate (current agent)
	Tools      []string // effective tool scope (intersection of all hops)
	ChainHash  string   // SHA-256 of the serialized chain for audit
}

// VerifyDelegation checks that a single delegation token is valid:
// 1. Signature is valid against the delegator's public key
// 2. Token is not expired
// 3. The target recipient is within the delegation scope
func VerifyDelegation(delegatorPub ed25519.PublicKey, token *DelegationToken, recipient string) DelegationVerifyResult {
	if token == nil {
		return DelegationVerifyResult{Valid: false, Reason: "nil delegation token"}
	}

	// Check expiry
	if time.Now().UTC().After(token.ExpiresAt) {
		return DelegationVerifyResult{Valid: false, Reason: "delegation expired"}
	}

	// Check not issued in the future (with 30s tolerance)
	if token.IssuedAt.After(time.Now().UTC().Add(30 * time.Second)) {
		return DelegationVerifyResult{Valid: false, Reason: "delegation issued in the future"}
	}

	// Verify signature — try chain payload first, fall back to legacy
	sig, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return DelegationVerifyResult{Valid: false, Reason: "invalid signature encoding"}
	}

	payload := delegationPayload(token)
	if !ed25519.Verify(delegatorPub, payload, sig) {
		// Try legacy payload for backward compatibility with pre-chain tokens
		legacy := legacyPayload(token.Delegator, token.Delegate, token.Scope, token.IssuedAt, token.ExpiresAt)
		if !ed25519.Verify(delegatorPub, legacy, sig) {
			return DelegationVerifyResult{Valid: false, Reason: "signature verification failed"}
		}
	}

	// Check scope
	if !scopeAllows(token.Scope, recipient) {
		return DelegationVerifyResult{
			Valid:  false,
			Reason: fmt.Sprintf("recipient %q not in delegation scope", recipient),
		}
	}

	return DelegationVerifyResult{Valid: true, Reason: "valid delegation"}
}

// VerifyChain verifies a complete delegation chain from root to leaf.
// keyResolver maps agent names to their public keys.
//
// Checks per hop:
//  1. Signature valid (delegator's key signs the token)
//  2. Token not expired
//  3. Chain linkage: token.ParentTokenID matches previous token.TokenID
//  4. Depth within MaxDepth
//  5. Scope narrows or stays equal (delegate can't escalate privileges)
//  6. Tool scope narrows or stays equal
//  7. Delegate of hop N == Delegator of hop N+1 (continuity)
func VerifyChain(chain DelegationChain, keyResolver func(agent string) ed25519.PublicKey) ChainVerifyResult {
	if len(chain) == 0 {
		return ChainVerifyResult{Valid: false, Reason: "empty delegation chain"}
	}

	effectiveTools := chain[0].AllowedTools
	prevTokenID := ""

	for i, token := range chain {
		// Resolve delegator's public key
		pub := keyResolver(token.Delegator)
		if pub == nil {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: unknown delegator %q (no public key)", i, token.Delegator),
			}
		}

		// Verify signature
		sig, err := base64.StdEncoding.DecodeString(token.Signature)
		if err != nil {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: invalid signature encoding", i),
			}
		}
		payload := delegationPayload(&token)
		if !ed25519.Verify(pub, payload, sig) {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: signature verification failed for %q", i, token.Delegator),
			}
		}

		// Check expiry
		if time.Now().UTC().After(token.ExpiresAt) {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: delegation from %q expired", i, token.Delegator),
			}
		}

		// Check depth
		if token.ChainDepth != i {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: expected chain_depth %d, got %d", i, i, token.ChainDepth),
			}
		}
		if token.ChainDepth > token.MaxDepth {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: chain_depth %d exceeds max_depth %d", i, token.ChainDepth, token.MaxDepth),
			}
		}

		// Check parent linkage
		if i == 0 {
			if token.ParentTokenID != "" {
				return ChainVerifyResult{
					Valid:  false,
					Reason: "hop 0: root token must have empty parent_token_id",
				}
			}
		} else {
			if token.ParentTokenID != prevTokenID {
				return ChainVerifyResult{
					Valid:  false,
					Reason: fmt.Sprintf("hop %d: parent_token_id mismatch (expected %s)", i, prevTokenID[:16]+"..."),
				}
			}
		}

		// Check continuity: previous delegate == current delegator
		if i > 0 && chain[i-1].Delegate != token.Delegator {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: delegator %q != previous delegate %q", i, token.Delegator, chain[i-1].Delegate),
			}
		}

		// Check scope doesn't escalate (each hop must be subset of parent)
		if i > 0 && !scopeIsSubset(token.Scope, chain[i-1].Scope) {
			return ChainVerifyResult{
				Valid:  false,
				Reason: fmt.Sprintf("hop %d: scope escalation (not subset of parent)", i),
			}
		}

		// Narrow effective tools
		if len(token.AllowedTools) > 0 {
			effectiveTools = intersectTools(effectiveTools, token.AllowedTools)
		}

		prevTokenID = token.TokenID
	}

	// Compute chain hash for audit
	chainData, _ := json.Marshal(chain)
	chainHash := sha256.Sum256(chainData)

	last := chain[len(chain)-1]
	return ChainVerifyResult{
		Valid:     true,
		Reason:    "valid delegation chain",
		Depth:     len(chain),
		Root:      chain[0].Delegator,
		Delegate:  last.Delegate,
		Tools:     effectiveTools,
		ChainHash: hex.EncodeToString(chainHash[:]),
	}
}

// FormatChain returns a human-readable chain summary like "human -> agent-a -> agent-b".
func FormatChain(chain DelegationChain) string {
	if len(chain) == 0 {
		return ""
	}
	parts := make([]string, 0, len(chain)+1)
	parts = append(parts, chain[0].Delegator)
	for _, t := range chain {
		parts = append(parts, t.Delegate)
	}
	return strings.Join(parts, " -> ")
}

// scopeAllows checks if recipient is covered by the scope list.
func scopeAllows(scope []string, recipient string) bool {
	for _, s := range scope {
		if s == "*" || s == recipient {
			return true
		}
	}
	return false
}

// scopeIsSubset checks if child scope is a subset of parent scope.
// Wildcard parent allows anything. Wildcard child with non-wildcard parent = escalation.
func scopeIsSubset(child, parent []string) bool {
	// Wildcard parent allows everything
	for _, p := range parent {
		if p == "*" {
			return true
		}
	}
	// Wildcard child with non-wildcard parent = escalation
	for _, c := range child {
		if c == "*" {
			return false
		}
	}
	// Every child scope must exist in parent
	parentSet := make(map[string]bool, len(parent))
	for _, p := range parent {
		parentSet[p] = true
	}
	for _, c := range child {
		if !parentSet[c] {
			return false
		}
	}
	return true
}

// intersectTools returns the intersection of two tool lists.
// If either is nil/empty, the other is returned (nil = all tools).
func intersectTools(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	set := make(map[string]bool, len(a))
	for _, t := range a {
		set[t] = true
	}
	var result []string
	for _, t := range b {
		if set[t] {
			result = append(result, t)
		}
	}
	return result
}
