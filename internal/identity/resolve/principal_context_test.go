package resolve

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// principal_context_test.go covers Phase 4E-0: the provider-neutral
// PrincipalContext model. The tests pin three contracts:
//
//  1. Context propagates from config -> resolver record -> Result.
//  2. Behavior is identical regardless of Provider string (no vendor
//     branching anywhere in the resolve stack).
//  3. Adding/removing context never changes the Principal fields ACL
//     and delegation read (ID, AuthMethod, TrustLevel, WorkspaceID).
//
// Plus a structural guard that no field on PrincipalContext could
// hold raw JWTs or raw claims JSON.

// fixtureConfigContext is the example context the spec §6.5 YAML
// shows. Reused across cases so each test focuses on the contract,
// not the field bag.
func fixtureConfigContext() ConfigPrincipalContext {
	return ConfigPrincipalContext{
		Issuer:    "https://issuer.example.com/",
		Subject:   "agent/claude-code",
		Audience:  "oktsec",
		ClientID:  "claude-code-local",
		TenantID:  "local-dev",
		Groups:    []string{"ai-agents"},
		Scopes:    []string{"mcp:tools", "hooks:events"},
		Provider:  "custom_oidc",
		Source:    "static_config",
		Verified:  true,
		ExpiresAt: "2099-01-01T00:00:00Z",
	}
}

// resolveWithContext builds a token-authenticated resolve and returns
// the Principal so each test can assert on the post-resolve shape.
func resolveWithContext(t *testing.T, principalID string, ctx ConfigPrincipalContext) Principal {
	t.Helper()
	raw, hash, err := GenerateRawToken(TokenTypeGatewayBearer)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cp := ConfigPrincipal{
		ID:          principalID,
		DisplayName: principalID,
		Kind:        string(PrincipalKindAgent),
		WorkspaceID: "wks-1",
		Tokens: []ConfigToken{{
			ID:        principalID + "-tok",
			Type:      "gateway_bearer",
			Hash:      hash,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}},
		Context: ctx,
	}
	store := NewMemoryTokenStoreWithClock(PrincipalsFromConfig([]ConfigPrincipal{cp}), nil)
	r := NewDefaultResolver(store, nil)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+raw)
	got, err := r.Resolve(context.Background(), Config{
		Profile:           ProfileLocal,
		AllowedTokenTypes: []TokenType{TokenTypeGatewayBearer},
	}, Evidence{Surface: SurfaceMCPHTTP, Header: hdr, RemoteAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return got.Principal
}

// TestPrincipalContext_PropagatedThroughTokenLookup — config carries
// context, token-authenticated resolve must surface it on the
// resolved Principal.
func TestPrincipalContext_PropagatedThroughTokenLookup(t *testing.T) {
	p := resolveWithContext(t, "claude-code", fixtureConfigContext())

	if p.Context.IsZero() {
		t.Fatal("Principal.Context is zero after token lookup; propagation broken")
	}
	if p.Context.Issuer != "https://issuer.example.com/" {
		t.Errorf("Issuer = %q", p.Context.Issuer)
	}
	if p.Context.Subject != "agent/claude-code" {
		t.Errorf("Subject = %q", p.Context.Subject)
	}
	if got, want := p.Context.Groups, []string{"ai-agents"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Groups = %v, want %v", got, want)
	}
	if got, want := p.Context.Scopes, []string{"mcp:tools", "hooks:events"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Scopes = %v, want %v", got, want)
	}
	if !p.Context.Verified {
		t.Errorf("Verified = false; static_config marked verified must round-trip")
	}
}

// TestPrincipalContext_LookupWithoutContextReturnsZero — empty config
// context must round-trip as a zero PrincipalContext (the absence
// case the dashboard renders as "External identity context not
// configured").
func TestPrincipalContext_LookupWithoutContextReturnsZero(t *testing.T) {
	p := resolveWithContext(t, "no-context-agent", ConfigPrincipalContext{})
	if !p.Context.IsZero() {
		t.Errorf("Principal.Context = %#v, want zero", p.Context)
	}
}

// TestPrincipalContext_VendorNeutralBehavior — two principals that
// differ only in Provider ("okta" vs "custom_oidc") must produce
// identical Principal shape apart from Context.Provider. No code
// path may branch on a vendor string.
func TestPrincipalContext_VendorNeutralBehavior(t *testing.T) {
	okta := fixtureConfigContext()
	okta.Provider = "okta"
	custom := fixtureConfigContext()
	custom.Provider = "custom_oidc"

	pOkta := resolveWithContext(t, "p-okta", okta)
	pCustom := resolveWithContext(t, "p-custom", custom)

	// Strip the only field allowed to differ, then compare every
	// other Principal field — including the rest of Context.
	pOkta.ID = ""
	pCustom.ID = ""
	pOkta.DisplayName = ""
	pCustom.DisplayName = ""
	pOkta.TokenID = ""
	pCustom.TokenID = ""
	pOkta.Context.Provider = ""
	pCustom.Context.Provider = ""

	if !reflect.DeepEqual(pOkta, pCustom) {
		t.Errorf("Principal differs across providers beyond display fields:\n okta=%#v\n custom=%#v", pOkta, pCustom)
	}
}

// TestPrincipalContext_DoesNotChangeAuthorityFields — adding or
// removing context never mutates the Principal fields the policy
// stack actually consumes (ID, AuthMethod, TrustLevel, WorkspaceID).
// This locks in "context is enrichment, not authority".
func TestPrincipalContext_DoesNotChangeAuthorityFields(t *testing.T) {
	pBare := resolveWithContext(t, "claude-code", ConfigPrincipalContext{})
	pCtx := resolveWithContext(t, "claude-code", fixtureConfigContext())

	if pBare.ID != pCtx.ID {
		t.Errorf("ID changed by context: %q vs %q", pBare.ID, pCtx.ID)
	}
	if pBare.AuthMethod != pCtx.AuthMethod {
		t.Errorf("AuthMethod changed by context: %q vs %q", pBare.AuthMethod, pCtx.AuthMethod)
	}
	if pBare.TrustLevel != pCtx.TrustLevel {
		t.Errorf("TrustLevel changed by context: %q vs %q", pBare.TrustLevel, pCtx.TrustLevel)
	}
	if pBare.WorkspaceID != pCtx.WorkspaceID {
		t.Errorf("WorkspaceID changed by context: %q vs %q", pBare.WorkspaceID, pCtx.WorkspaceID)
	}
	if pBare.Kind != pCtx.Kind {
		t.Errorf("Kind changed by context: %q vs %q", pBare.Kind, pCtx.Kind)
	}
}

// TestPrincipalContext_NoRawClaimsField — structural guard: no field
// on PrincipalContext may hold a raw JWT or raw claims JSON. Only
// ClaimsHash (a digest) is permitted. A future PR that adds
// "RawJWT" or "Claims" must update this list deliberately.
func TestPrincipalContext_NoRawClaimsField(t *testing.T) {
	rt := reflect.TypeOf(PrincipalContext{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		switch name {
		case "claimshash":
			// hash, not the claims themselves — allowed
		default:
			if strings.Contains(name, "jwt") || strings.Contains(name, "rawclaim") || name == "claims" {
				t.Errorf("PrincipalContext field %q would surface raw claims/JWT; not allowed", rt.Field(i).Name)
			}
		}
	}
}

// TestPrincipalContext_DeepCopiedSlices — the resolver record must
// not share Groups/Scopes backing arrays with the inbound config so
// a later mutation on the config side cannot reach principal state.
func TestPrincipalContext_DeepCopiedSlices(t *testing.T) {
	cfg := fixtureConfigContext()
	records := PrincipalsFromConfig([]ConfigPrincipal{{
		ID: "x", Tokens: nil, Context: cfg,
	}})
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if len(records[0].Context.Groups) != 1 {
		t.Fatalf("Groups not copied")
	}
	cfg.Groups[0] = "MUTATED"
	if records[0].Context.Groups[0] == "MUTATED" {
		t.Errorf("config slice mutation reached resolver record (shared backing array)")
	}
}
