package resolve

import (
	"strings"
)

// ConfigPrincipal is the minimal projection of internal/config that the
// resolver needs. The config package builds these values from the YAML
// PrincipalConfig and passes them in; resolve does not import config to
// avoid a cycle. See PrincipalsFromConfig for the canonical bridge.
type ConfigPrincipal struct {
	ID              string
	DisplayName     string
	Kind            string
	WorkspaceID     string
	AllowedSurfaces []string
	Tokens          []ConfigToken
	Context         ConfigPrincipalContext
}

// ConfigPrincipalContext mirrors config.PrincipalContextConfig but stays
// free of YAML tags so resolve does not import config. Empty values
// translate to a zero PrincipalContext (no enrichment).
type ConfigPrincipalContext struct {
	Issuer     string
	Subject    string
	Audience   string
	ClientID   string
	TenantID   string
	Groups     []string
	Scopes     []string
	Provider   string
	Source     string
	Verified   bool
	ExpiresAt  string
	ClaimsHash string
}

// ConfigToken mirrors config.PrincipalTokenConfig but stays free of YAML
// tags so resolve can be imported in tests without pulling config.
type ConfigToken struct {
	ID        string
	Type      string // "gateway_bearer" | "proxy_basic" | "hook_bearer"
	Hash      string
	CreatedAt string
	ExpiresAt string
	RevokedAt string
}

// PrincipalsFromConfig converts the on-disk shape into PrincipalRecords.
// Tokens with an unknown Type are dropped with no error so a typo in the
// YAML cannot accidentally become an authenticatable secret.
func PrincipalsFromConfig(in []ConfigPrincipal) []PrincipalRecord {
	out := make([]PrincipalRecord, 0, len(in))
	for _, p := range in {
		surfaces := make([]Surface, 0, len(p.AllowedSurfaces))
		for _, s := range p.AllowedSurfaces {
			surfaces = append(surfaces, Surface(s))
		}
		tokens := make([]TokenRecord, 0, len(p.Tokens))
		for _, t := range p.Tokens {
			tt, ok := tokenTypeFromString(t.Type)
			if !ok {
				continue
			}
			tokens = append(tokens, TokenRecord{
				ID:          t.ID,
				Type:        tt,
				PrincipalID: p.ID,
				Hash:        t.Hash,
				CreatedAt:   t.CreatedAt,
				ExpiresAt:   t.ExpiresAt,
				RevokedAt:   t.RevokedAt,
			})
		}
		kind := PrincipalKind(strings.TrimSpace(p.Kind))
		if kind == "" {
			kind = PrincipalKindAgent
		}
		out = append(out, PrincipalRecord{
			ID:              p.ID,
			DisplayName:     p.DisplayName,
			Kind:            kind,
			WorkspaceID:     p.WorkspaceID,
			AllowedSurfaces: surfaces,
			Tokens:          tokens,
			Context:         principalContextFromConfig(p.Context),
		})
	}
	return out
}

// principalContextFromConfig copies the neutral context fields. Slice
// fields are length-preserving copies so the resolver record cannot be
// mutated through the original config slice.
func principalContextFromConfig(c ConfigPrincipalContext) PrincipalContext {
	out := PrincipalContext{
		Issuer:     c.Issuer,
		Subject:    c.Subject,
		Audience:   c.Audience,
		ClientID:   c.ClientID,
		TenantID:   c.TenantID,
		Provider:   c.Provider,
		Source:     c.Source,
		Verified:   c.Verified,
		ExpiresAt:  c.ExpiresAt,
		ClaimsHash: c.ClaimsHash,
	}
	if len(c.Groups) > 0 {
		out.Groups = append([]string(nil), c.Groups...)
	}
	if len(c.Scopes) > 0 {
		out.Scopes = append([]string(nil), c.Scopes...)
	}
	return out
}

func tokenTypeFromString(s string) (TokenType, bool) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "gateway_bearer":
		return TokenTypeGatewayBearer, true
	case "proxy_basic":
		return TokenTypeProxyBasic, true
	case "hook_bearer":
		return TokenTypeHookBearer, true
	}
	return "", false
}
