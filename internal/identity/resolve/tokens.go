package resolve

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TokenType narrows what surface a token may authenticate. A gateway bearer
// token must not be accepted by the egress proxy, and vice versa, so each
// is namespaced both at the type level and in the prefix of its raw value.
type TokenType string

const (
	TokenTypeGatewayBearer TokenType = "gateway_bearer"
	TokenTypeProxyBasic    TokenType = "proxy_basic"
	TokenTypeHookBearer    TokenType = "hook_bearer"
)

// rawTokenPrefix returns the human-visible prefix for newly generated raw
// tokens. The prefix lets operators tell at a glance what a leaked secret
// would have authorized, and it lets the resolver fail fast on type
// mismatches before doing any hash work.
func rawTokenPrefix(t TokenType) string {
	switch t {
	case TokenTypeGatewayBearer:
		return "okt_gw_"
	case TokenTypeProxyBasic:
		return "okt_proxy_"
	case TokenTypeHookBearer:
		return "okt_hook_"
	}
	return "okt_"
}

// TokenRecord is the on-disk shape of a token associated with a Principal.
// The raw secret is shown to the operator exactly once at creation time;
// only the salted SHA-256 hash is persisted.
type TokenRecord struct {
	ID          string    `yaml:"id" json:"id"`
	Type        TokenType `yaml:"type" json:"type"`
	PrincipalID string    `yaml:"principal_id" json:"principal_id"`
	Hash        string    `yaml:"hash" json:"hash"` // sha256:<salt>:<hex>
	CreatedAt   string    `yaml:"created_at" json:"created_at"`
	ExpiresAt   string    `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
	RevokedAt   string    `yaml:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	LastUsedAt  string    `yaml:"last_used_at,omitempty" json:"last_used_at,omitempty"`
}

// Active reports whether the token may still authenticate. Expired or
// revoked tokens are inert.
func (r TokenRecord) Active(now time.Time) bool {
	if r.RevokedAt != "" {
		return false
	}
	if r.ExpiresAt == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		// Unparseable expiry is treated as expired so a malformed config
		// fails closed instead of silently extending lifetime.
		return false
	}
	return now.Before(exp)
}

// PrincipalRecord is the on-disk shape of a Principal. Tokens live inside
// the Principal because lookups always start from a token and resolve to
// the owning Principal.
type PrincipalRecord struct {
	ID              string           `yaml:"id" json:"id"`
	DisplayName     string           `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Kind            PrincipalKind    `yaml:"kind,omitempty" json:"kind,omitempty"`
	WorkspaceID     string           `yaml:"workspace_id,omitempty" json:"workspace_id,omitempty"`
	Tokens          []TokenRecord    `yaml:"tokens,omitempty" json:"tokens,omitempty"`
	AllowedSurfaces []Surface        `yaml:"allowed_surfaces,omitempty" json:"allowed_surfaces,omitempty"`
	Context         PrincipalContext `yaml:"context,omitempty" json:"context,omitempty"`
}

// TokenStore looks up tokens by ID and, given a candidate raw secret,
// returns the owning Principal in constant time relative to the number of
// tokens of that type. Implementations must be safe for concurrent reads.
type TokenStore interface {
	// Lookup attempts to authenticate `raw` as a token of the given type.
	// On success it returns the matching PrincipalRecord and the TokenRecord
	// that authenticated it. On failure it returns ErrNoToken.
	Lookup(t TokenType, raw string) (PrincipalRecord, TokenRecord, error)

	// PrincipalByID returns the Principal record for a known ID. Used by
	// non-token auth methods (Ed25519, mTLS) once they have established an ID.
	PrincipalByID(id string) (PrincipalRecord, bool)
}

// ErrNoToken is returned by TokenStore.Lookup when the candidate secret
// does not match any active token of the requested type.
var ErrNoToken = errors.New("identity: no matching active token")

// MemoryTokenStore is the simple in-memory store used by tests and the
// initial release. Tokens come from config; on config reload, callers
// rebuild the store and swap it in.
//
// Active state (revoked/expired) is rechecked on every Lookup against the
// store's clock — building the index does not snapshot activity, so a
// token that expires at noon stops authenticating at noon even if the
// store was built at 11:59.
type MemoryTokenStore struct {
	mu    sync.RWMutex
	now   func() time.Time
	byID  map[string]PrincipalRecord          // principal lookup
	byTok map[TokenType]map[string]tokenIndex // type -> tokenID -> index entry
}

// tokenIndex caches lookup data for a token. Active state lives in the
// authoritative TokenRecord on the PrincipalRecord; we copy expires_at and
// revoked_at here so Lookup can fail closed without holding the principal
// lock during hash comparison.
type tokenIndex struct {
	principalID string
	hash        string // sha256:<salt>:<hex>
	expiresAt   string // RFC3339 or "" for no expiry
	revokedAt   string // RFC3339 or "" for active
}

// NewMemoryTokenStore builds a store from the given Principals. The store
// uses time.Now as its clock; callers that need an injectable clock should
// use NewMemoryTokenStoreWithClock.
//
// Tokens that are already expired or revoked at construction time are
// included in the index but will fail the Active() check on Lookup. The
// `now` argument is accepted for backwards compatibility but no longer
// filters tokens — Lookup uses the store's clock at call time.
func NewMemoryTokenStore(principals []PrincipalRecord, now time.Time) *MemoryTokenStore {
	return NewMemoryTokenStoreWithClock(principals, nil)
}

// NewMemoryTokenStoreWithClock builds a store with an injectable clock.
// When clock is nil, time.Now is used. Tests should pass a fixed clock so
// expiry/revocation semantics are reproducible.
func NewMemoryTokenStoreWithClock(principals []PrincipalRecord, clock func() time.Time) *MemoryTokenStore {
	if clock == nil {
		clock = time.Now
	}
	s := &MemoryTokenStore{
		now:   clock,
		byID:  make(map[string]PrincipalRecord, len(principals)),
		byTok: make(map[TokenType]map[string]tokenIndex),
	}
	for _, p := range principals {
		s.byID[p.ID] = p
		for _, tok := range p.Tokens {
			bucket, ok := s.byTok[tok.Type]
			if !ok {
				bucket = make(map[string]tokenIndex)
				s.byTok[tok.Type] = bucket
			}
			bucket[tok.ID] = tokenIndex{
				principalID: p.ID,
				hash:        tok.Hash,
				expiresAt:   tok.ExpiresAt,
				revokedAt:   tok.RevokedAt,
			}
		}
	}
	return s
}

// Lookup walks the bucket of tokens for the given type and returns the
// first hash match that is still active. Each hash comparison is
// constant-time. Token candidates must start with the type-specific prefix;
// mismatches are rejected without a hash compare to avoid timing leaks
// across token classes. Active state is rechecked on every call against
// the store's clock so post-build expiry takes effect immediately.
func (s *MemoryTokenStore) Lookup(t TokenType, raw string) (PrincipalRecord, TokenRecord, error) {
	if raw == "" || !strings.HasPrefix(raw, rawTokenPrefix(t)) {
		return PrincipalRecord{}, TokenRecord{}, ErrNoToken
	}
	s.mu.RLock()
	bucket := s.byTok[t]
	now := s.now()
	s.mu.RUnlock()
	if bucket == nil {
		return PrincipalRecord{}, TokenRecord{}, ErrNoToken
	}
	for tokID, idx := range bucket {
		if !verifyHash(idx.hash, raw) {
			continue
		}
		// Even if the hash matches, the token may have been revoked or
		// passed its expiry since the index was built. Recheck both before
		// returning a Principal.
		if !indexActive(idx, now) {
			return PrincipalRecord{}, TokenRecord{}, ErrNoToken
		}
		s.mu.RLock()
		principal := s.byID[idx.principalID]
		s.mu.RUnlock()
		for _, tok := range principal.Tokens {
			if tok.ID == tokID {
				return principal, tok, nil
			}
		}
		// Index entry without owning principal token — treat as miss.
		return PrincipalRecord{}, TokenRecord{}, ErrNoToken
	}
	return PrincipalRecord{}, TokenRecord{}, ErrNoToken
}

// indexActive mirrors TokenRecord.Active using only the data cached in the
// index, so Lookup can decide without re-walking PrincipalRecord.Tokens.
func indexActive(idx tokenIndex, now time.Time) bool {
	if idx.revokedAt != "" {
		return false
	}
	if idx.expiresAt == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, idx.expiresAt)
	if err != nil {
		return false
	}
	return now.Before(exp)
}

// PrincipalByID returns the principal record by ID.
func (s *MemoryTokenStore) PrincipalByID(id string) (PrincipalRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.byID[id]
	return p, ok
}

// GenerateRawToken returns a freshly generated raw token (with type prefix)
// and its salted hash for storage. The caller is responsible for showing the
// raw value exactly once and persisting only the hash.
func GenerateRawToken(t TokenType) (raw string, hash string, err error) {
	// 32 random bytes -> 256 bits of entropy in the secret portion.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("identity: rand: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("identity: rand: %w", err)
	}
	raw = rawTokenPrefix(t) + hex.EncodeToString(secret)
	hash = formatHash(salt, raw)
	return raw, hash, nil
}

// HashRawToken hashes a raw token with the given salt. Exposed for tests
// and for tooling that imports an externally-issued secret.
func HashRawToken(raw string, salt []byte) string {
	return formatHash(salt, raw)
}

func formatHash(salt []byte, raw string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(raw))
	sum := h.Sum(nil)
	return "sha256:" + hex.EncodeToString(salt) + ":" + hex.EncodeToString(sum)
}

// verifyHash performs a constant-time compare between a stored hash record
// and a candidate raw token. It returns false on any parse error so a
// malformed stored record cannot accidentally authenticate.
func verifyHash(stored, candidate string) bool {
	parts := strings.SplitN(stored, ":", 3)
	if len(parts) != 3 || parts[0] != "sha256" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(candidate))
	got := h.Sum(nil)
	return subtle.ConstantTimeCompare(expected, got) == 1
}
