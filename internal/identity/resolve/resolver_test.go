package resolve

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"
)

// helper: builds a store with one principal and one active token of the
// given type, returning the raw token so tests can present it as a header.
func storeWithToken(t *testing.T, principalID string, kind PrincipalKind, tokType TokenType) (*MemoryTokenStore, string) {
	t.Helper()
	raw, hash, err := GenerateRawToken(tokType)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	rec := PrincipalRecord{
		ID:          principalID,
		DisplayName: principalID,
		Kind:        kind,
		Tokens: []TokenRecord{{
			ID:          principalID + "-tok-1",
			Type:        tokType,
			PrincipalID: principalID,
			Hash:        hash,
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		}},
	}
	return NewMemoryTokenStore([]PrincipalRecord{rec}, time.Now()), raw
}

func TestResolver_BearerTokenPrincipal(t *testing.T) {
	store, raw := storeWithToken(t, "local-codex", PrincipalKindAgent, TokenTypeGatewayBearer)
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)

	got, err := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeGatewayBearer},
	}, Evidence{Surface: SurfaceMCPHTTP, Header: hdr, RemoteAddr: "203.0.113.7:54321"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.ID != "local-codex" {
		t.Errorf("principal id = %q, want local-codex", got.Principal.ID)
	}
	if got.Principal.AuthMethod != AuthMethodBearerToken {
		t.Errorf("auth method = %q, want bearer_token", got.Principal.AuthMethod)
	}
	if got.Principal.TrustLevel != TrustAuthenticated {
		t.Errorf("trust level = %q, want authenticated", got.Principal.TrustLevel)
	}
	if got.Principal.TokenID == "" {
		t.Error("token id should be populated for token-based auth")
	}
}

// Bearer token always wins over a spoofed X-Oktsec-Agent header. The
// header value can still appear as a low-confidence reported actor — but
// it must NOT become the policy principal.
func TestResolver_BearerTokenWinsOverSpoofedAgentHeader(t *testing.T) {
	store, raw := storeWithToken(t, "local-codex", PrincipalKindAgent, TokenTypeGatewayBearer)
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)
	hdr.Set("X-Oktsec-Agent", "admin") // attacker's spoof

	got, err := r.Resolve(context.Background(), Config{
		Profile:                ProfileLocal,
		AllowedTokenTypes:      []TokenType{TokenTypeGatewayBearer},
		TrustedLoopbackHeaders: true, // even with this on, token wins
	}, Evidence{
		Surface: SurfaceMCPHTTP, Header: hdr,
		RemoteAddr:  "127.0.0.1:54321",
		ConfigAgent: "admin", // legacy ctx value also points at admin
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.ID != "local-codex" {
		t.Errorf("principal id = %q, want local-codex (bearer must win)", got.Principal.ID)
	}
	if got.ReportedActor.ID != "admin" {
		t.Errorf("reported actor id = %q, want admin (header surfaces as reported only)", got.ReportedActor.ID)
	}
}

// In enterprise profile the loopback-header path is disabled regardless of
// remote address, so an unauthenticated request resolves to anonymous.
func TestResolver_EnterpriseRejectsLoopbackHeader(t *testing.T) {
	store, _ := storeWithToken(t, "local-codex", PrincipalKindAgent, TokenTypeGatewayBearer)
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("X-Oktsec-Agent", "admin")

	got, err := r.Resolve(context.Background(), Config{
		Profile:                ProfileEnterprise,
		AllowedTokenTypes:      []TokenType{TokenTypeGatewayBearer},
		TrustedLoopbackHeaders: true, // honored only in local
	}, Evidence{
		Surface:    SurfaceMCPHTTP,
		Header:     hdr,
		RemoteAddr: "127.0.0.1:54321",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.AuthMethod != AuthMethodNone {
		t.Errorf("auth method = %q, want none in enterprise without token", got.Principal.AuthMethod)
	}
	if got.Principal.TrustLevel != TrustAnonymous {
		t.Errorf("trust level = %q, want anonymous", got.Principal.TrustLevel)
	}
}

// Loopback header is accepted in local profile when the remote really is
// loopback. Carries trust_local and a warning advising token migration.
func TestResolver_LocalLoopbackHeaderAccepted(t *testing.T) {
	store := NewMemoryTokenStore(nil, time.Now())
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("X-Oktsec-Agent", "claude-code")

	got, err := r.Resolve(context.Background(), Config{
		Profile:                ProfileLocal,
		TrustedLoopbackHeaders: true,
	}, Evidence{
		Surface:    SurfaceMCPHTTP,
		Header:     hdr,
		RemoteAddr: "127.0.0.1:65000",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.ID != "claude-code" {
		t.Errorf("principal id = %q, want claude-code", got.Principal.ID)
	}
	if got.Principal.TrustLevel != TrustLocal {
		t.Errorf("trust level = %q, want trusted_local", got.Principal.TrustLevel)
	}
	if len(got.Warnings) == 0 {
		t.Error("expected a warning when relying on loopback header identity")
	}
}

// Loopback header is rejected when the remote is not actually loopback —
// this prevents trusted_proxy misconfigurations from upgrading a public
// header to principal.
func TestResolver_LoopbackHeaderRejectedFromRemote(t *testing.T) {
	store := NewMemoryTokenStore(nil, time.Now())
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("X-Oktsec-Agent", "admin")

	got, err := r.Resolve(context.Background(), Config{
		Profile:                ProfileLocal,
		TrustedLoopbackHeaders: true,
	}, Evidence{
		Surface:     SurfaceMCPHTTP,
		Header:      hdr,
		RemoteAddr:  "10.0.0.5:43210",
		ConfigAgent: "admin", // gateway populates this from X-Oktsec-Agent
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.AuthMethod != AuthMethodNone {
		t.Errorf("auth method = %q, want none for non-loopback header", got.Principal.AuthMethod)
	}
	// The header still surfaces as a low-confidence reported actor for UI.
	if got.ReportedActor.ID != "admin" || got.ReportedActor.Confidence != "low" {
		t.Errorf("reported actor = %+v, want id=admin confidence=low", got.ReportedActor)
	}
}

// Revoked tokens never authenticate, even if the raw secret is presented.
func TestResolver_RevokedTokenRejected(t *testing.T) {
	raw, hash, err := GenerateRawToken(TokenTypeGatewayBearer)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rec := PrincipalRecord{
		ID: "local-codex",
		Tokens: []TokenRecord{{
			ID:          "tok-1",
			Type:        TokenTypeGatewayBearer,
			PrincipalID: "local-codex",
			Hash:        hash,
			CreatedAt:   "2026-01-01T00:00:00Z",
			RevokedAt:   "2026-04-25T00:00:00Z",
		}},
	}
	store := NewMemoryTokenStore([]PrincipalRecord{rec}, time.Now())
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)

	got, err := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeGatewayBearer},
	}, Evidence{Surface: SurfaceMCPHTTP, Header: hdr, RemoteAddr: "127.0.0.1:1234"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.ID == "local-codex" {
		t.Error("revoked token must not authenticate")
	}
}

// Expired tokens never authenticate.
func TestResolver_ExpiredTokenRejected(t *testing.T) {
	raw, hash, err := GenerateRawToken(TokenTypeGatewayBearer)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rec := PrincipalRecord{
		ID: "local-codex",
		Tokens: []TokenRecord{{
			ID:          "tok-1",
			Type:        TokenTypeGatewayBearer,
			PrincipalID: "local-codex",
			Hash:        hash,
			CreatedAt:   "2026-01-01T00:00:00Z",
			ExpiresAt:   "2026-01-02T00:00:00Z",
		}},
	}
	store := NewMemoryTokenStore([]PrincipalRecord{rec}, time.Now())
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)

	got, _ := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeGatewayBearer},
	}, Evidence{Surface: SurfaceMCPHTTP, Header: hdr, RemoteAddr: "127.0.0.1:1234"})
	if got.Principal.ID == "local-codex" {
		t.Error("expired token must not authenticate")
	}
}

// Tokens of the wrong type for this surface are rejected even when the
// secret value is otherwise valid. Prevents a leaked egress proxy token
// from authenticating to the gateway and vice versa.
func TestResolver_TokenTypeMismatch(t *testing.T) {
	store, raw := storeWithToken(t, "local-codex", PrincipalKindAgent, TokenTypeGatewayBearer)
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)

	got, _ := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeProxyBasic}, // surface only allows proxy tokens
	}, Evidence{Surface: SurfaceHTTPEgress, Header: hdr, RemoteAddr: "127.0.0.1:1234"})
	if got.Principal.AuthMethod == AuthMethodBearerToken {
		t.Error("gateway bearer must not authenticate on a proxy-only surface")
	}
}

// Proxy basic auth path: the username carries the raw token.
func TestResolver_ProxyBasicAuth(t *testing.T) {
	store, raw := storeWithToken(t, "local-codex", PrincipalKindAgent, TokenTypeProxyBasic)
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	encoded := base64.StdEncoding.EncodeToString([]byte(raw + ":"))
	hdr.Set("Proxy-Authorization", "Basic "+encoded)

	got, err := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeProxyBasic},
	}, Evidence{Surface: SurfaceHTTPEgress, Header: hdr, RemoteAddr: "127.0.0.1:1234"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Principal.AuthMethod != AuthMethodProxyToken {
		t.Errorf("auth method = %q, want proxy_token", got.Principal.AuthMethod)
	}
}

// Reported-actor payload key takes precedence over header fallbacks. The
// resolver must still return Principal=unknown when no token is present.
func TestResolver_ReportedActorFromPayload(t *testing.T) {
	store := NewMemoryTokenStore(nil, time.Now())
	r := NewDefaultResolver(store, nil)

	got, _ := r.Resolve(context.Background(), Config{
		Profile:                  ProfileLocal,
		ReportedActorPayloadKeys: []string{"_oktsec_agent", "actor"},
	}, Evidence{
		Surface: SurfaceHooks,
		Payload: map[string]any{"_oktsec_agent": "review-subagent"},
	})
	if got.Principal.AuthMethod != AuthMethodNone {
		t.Errorf("auth method = %q, want none", got.Principal.AuthMethod)
	}
	if got.ReportedActor.ID != "review-subagent" {
		t.Errorf("reported actor = %q, want review-subagent", got.ReportedActor.ID)
	}
	if got.ReportedActor.Source != "payload" {
		t.Errorf("reported actor source = %q, want payload", got.ReportedActor.Source)
	}
}

// A token that is active when the store is built but expires while the
// store is still in memory must stop authenticating immediately. This
// guards against the bug where Active() was checked only at index time
// and the bucket cached a since-expired token.
func TestStore_ExpiryRevalidatedAtLookupTime(t *testing.T) {
	raw, hash, err := GenerateRawToken(TokenTypeGatewayBearer)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rec := PrincipalRecord{
		ID: "local-codex",
		Tokens: []TokenRecord{{
			ID:          "tok-1",
			Type:        TokenTypeGatewayBearer,
			PrincipalID: "local-codex",
			Hash:        hash,
			CreatedAt:   "2026-04-26T00:00:00Z",
			ExpiresAt:   "2026-04-26T12:00:00Z",
		}},
	}

	// Movable clock the store reads on every Lookup.
	now := time.Date(2026, 4, 26, 11, 59, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := NewMemoryTokenStoreWithClock([]PrincipalRecord{rec}, clock)
	r := NewDefaultResolver(store, clock)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)

	// Before expiry — must authenticate.
	got, _ := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeGatewayBearer},
	}, Evidence{Surface: SurfaceMCPHTTP, Header: hdr, RemoteAddr: "127.0.0.1:1"})
	if got.Principal.ID != "local-codex" {
		t.Fatalf("pre-expiry: principal id = %q, want local-codex", got.Principal.ID)
	}

	// Advance clock past expiry; same store, same token, must now fail.
	now = time.Date(2026, 4, 26, 12, 0, 1, 0, time.UTC)
	got, _ = r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeGatewayBearer},
	}, Evidence{Surface: SurfaceMCPHTTP, Header: hdr, RemoteAddr: "127.0.0.1:1"})
	if got.Principal.AuthMethod == AuthMethodBearerToken {
		t.Error("post-expiry: token still authenticates; lookup-time revalidation broken")
	}
}

// MeetsMinimumTrust orders levels: anonymous < observed < inferred <
// trusted_local < authenticated. A higher rank also meets the lower bars.
func TestResult_MeetsMinimumTrust(t *testing.T) {
	cases := []struct {
		got, min TrustLevel
		want     bool
	}{
		{TrustAuthenticated, TrustAuthenticated, true},
		{TrustAuthenticated, TrustLocal, true},
		{TrustLocal, TrustAuthenticated, false},
		{TrustLocal, TrustLocal, true},
		{TrustObserved, TrustLocal, false},
		{TrustAnonymous, TrustObserved, false},
		{TrustLevel("garbage"), TrustObserved, false}, // unknown ranks as 0
	}
	for _, tc := range cases {
		r := Result{Principal: Principal{TrustLevel: tc.got}}
		if got := r.MeetsMinimumTrust(tc.min); got != tc.want {
			t.Errorf("got=%s min=%s -> %v, want %v", tc.got, tc.min, got, tc.want)
		}
	}
}

// RequireMinimumTrust returns an InsufficientTrustError that surfaces can
// inspect to choose the correct fail-closed response code.
func TestResult_RequireMinimumTrust(t *testing.T) {
	ok := Result{Principal: Principal{TrustLevel: TrustAuthenticated, AuthMethod: AuthMethodBearerToken}}
	if err := ok.RequireMinimumTrust(TrustAuthenticated); err != nil {
		t.Errorf("authenticated should satisfy authenticated: %v", err)
	}

	bad := Result{Principal: Principal{TrustLevel: TrustAnonymous, AuthMethod: AuthMethodNone}}
	err := bad.RequireMinimumTrust(TrustAuthenticated)
	if err == nil {
		t.Fatal("anonymous must not satisfy authenticated")
	}
	insuf, ok2 := err.(*InsufficientTrustError)
	if !ok2 {
		t.Fatalf("error type = %T, want *InsufficientTrustError", err)
	}
	if insuf.Required != TrustAuthenticated || insuf.Got != TrustAnonymous {
		t.Errorf("error fields = %+v", insuf)
	}
}

// Helpful for test scaffolding: IsLoopback covers the literal cases and
// rejects DNS-style "localhost" (which can be poisoned).
func TestIsLoopback(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"127.0.0.1:1234", true},
		{"127.0.0.1", true},
		{"[::1]:1234", true},
		{"::1", true},
		{"localhost:1234", false},
		{"10.0.0.5:1234", false},
		{"203.0.113.1:1234", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsLoopback(tc.in); got != tc.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
