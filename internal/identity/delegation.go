package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// DelegationToken represents a cryptographically signed authorization from one
// agent (delegator) to another (delegate), granting scoped messaging permissions.
// Inspired by Verifiable Intent's 3-layer delegation chain model.
type DelegationToken struct {
	Delegator string    `json:"delegator"`           // parent agent name
	Delegate  string    `json:"delegate"`            // child agent name
	Scope     []string  `json:"scope"`               // allowed recipients, or ["*"] for all
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature,omitempty"` // base64(ed25519 sig by delegator)
}

// delegationPayload builds the canonical byte payload for signing/verification.
// Format: delegator\ndelegate\nscope_csv\nissuedAt\nexpiresAt
func delegationPayload(delegator, delegate string, scope []string, issuedAt, expiresAt time.Time) []byte {
	scopeCSV := strings.Join(scope, ",")
	s := fmt.Sprintf("%s\n%s\n%s\n%s\n%s",
		delegator, delegate, scopeCSV,
		issuedAt.UTC().Format(time.RFC3339),
		expiresAt.UTC().Format(time.RFC3339),
	)
	return []byte(s)
}

// CreateDelegation creates a signed delegation token from delegator to delegate.
// The delegator's private key signs the canonical payload.
func CreateDelegation(delegatorKey ed25519.PrivateKey, delegator, delegate string, scope []string, ttl time.Duration) *DelegationToken {
	now := time.Now().UTC()
	token := &DelegationToken{
		Delegator: delegator,
		Delegate:  delegate,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	payload := delegationPayload(delegator, delegate, scope, token.IssuedAt, token.ExpiresAt)
	sig := ed25519.Sign(delegatorKey, payload)
	token.Signature = base64.StdEncoding.EncodeToString(sig)

	return token
}

// DelegationVerifyResult holds the outcome of delegation verification.
type DelegationVerifyResult struct {
	Valid  bool
	Reason string
}

// VerifyDelegation checks that a delegation token is valid:
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

	// Verify signature
	sig, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return DelegationVerifyResult{Valid: false, Reason: "invalid signature encoding"}
	}

	payload := delegationPayload(token.Delegator, token.Delegate, token.Scope, token.IssuedAt, token.ExpiresAt)
	if !ed25519.Verify(delegatorPub, payload, sig) {
		return DelegationVerifyResult{Valid: false, Reason: "signature verification failed"}
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

// scopeAllows checks if recipient is covered by the scope list.
func scopeAllows(scope []string, recipient string) bool {
	for _, s := range scope {
		if s == "*" || s == recipient {
			return true
		}
	}
	return false
}
