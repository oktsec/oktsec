package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// principal_context_test.go covers Phase 4E-0 config parsing for the
// provider-neutral PrincipalContextConfig. The YAML key must be
// `context` (never `okta`/`auth0`/`idp`) and Save+Load must round
// trip every field declared on the struct so a future change can't
// silently drop a value.

const principalContextYAML = `
version: "1"
server:
  port: 9090
identity:
  keys_dir: ./test-keys
  require_signature: true
  principals:
    - id: claude-code
      display_name: Claude Code
      kind: agent
      workspace_id: local
      context:
        issuer: https://issuer.example.com/
        subject: agent/claude-code
        audience: oktsec
        client_id: claude-code-local
        tenant_id: local-dev
        groups: ["ai-agents"]
        scopes: ["mcp:tools", "hooks:events"]
        provider: custom_oidc
        source: static_config
        verified: true
        expires_at: 2099-01-01T00:00:00Z
        claims_hash: deadbeef
`

func writePrincipalContextConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(principalContextYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPrincipalContext_LoadParsesAllFields — every YAML field listed
// in the spec lands on the parsed PrincipalContextConfig.
func TestPrincipalContext_LoadParsesAllFields(t *testing.T) {
	cfg, err := Load(writePrincipalContextConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Identity.Principals) != 1 {
		t.Fatalf("principals = %d, want 1", len(cfg.Identity.Principals))
	}
	got := cfg.Identity.Principals[0].Context
	want := PrincipalContextConfig{
		Issuer:     "https://issuer.example.com/",
		Subject:    "agent/claude-code",
		Audience:   "oktsec",
		ClientID:   "claude-code-local",
		TenantID:   "local-dev",
		Groups:     []string{"ai-agents"},
		Scopes:     []string{"mcp:tools", "hooks:events"},
		Provider:   "custom_oidc",
		Source:     "static_config",
		Verified:   true,
		ExpiresAt:  "2099-01-01T00:00:00Z",
		ClaimsHash: "deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("context mismatch:\n got=%#v\nwant=%#v", got, want)
	}
}

// TestPrincipalContext_YAMLKeyIsContextNotVendorName — the on-disk
// key must be exactly `context`. Mistyped vendor-named keys must not
// silently bind to PrincipalContextConfig.
func TestPrincipalContext_YAMLKeyIsContextNotVendorName(t *testing.T) {
	for _, key := range []string{"okta", "auth0", "idp", "oidc"} {
		body := strings.Replace(principalContextYAML, "      context:", "      "+key+":", 1)
		dir := t.TempDir()
		path := filepath.Join(dir, "oktsec.yaml")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load with key %q: %v", key, err)
		}
		if len(cfg.Identity.Principals) != 1 {
			t.Fatalf("key %q: principals = %d", key, len(cfg.Identity.Principals))
		}
		if !principalContextConfigEmpty(cfg.Identity.Principals[0].Context) {
			t.Errorf("YAML key %q populated PrincipalContext; only `context` is the supported key", key)
		}
	}
}

// TestPrincipalContext_OmittedYieldsZero — a principal without a
// `context:` block must produce an empty PrincipalContextConfig (the
// "External identity context not configured" case).
func TestPrincipalContext_OmittedYieldsZero(t *testing.T) {
	body := `
version: "1"
identity:
  keys_dir: ./test-keys
  require_signature: true
  principals:
    - id: claude-code
      display_name: Claude Code
      kind: agent
`
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !principalContextConfigEmpty(cfg.Identity.Principals[0].Context) {
		t.Errorf("missing context block produced non-empty PrincipalContextConfig: %#v", cfg.Identity.Principals[0].Context)
	}
}

// TestPrincipalContext_SaveLoadRoundTrip — Save followed by Load
// preserves every field. Guards against a missed YAML tag or a future
// field added without serialization support.
func TestPrincipalContext_SaveLoadRoundTrip(t *testing.T) {
	cfg, err := Load(writePrincipalContextConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.yaml")
	if err := cfg.Save(out); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(out)
	if err != nil {
		t.Fatalf("re-load: %v", err)
	}
	if !reflect.DeepEqual(cfg.Identity.Principals[0].Context, cfg2.Identity.Principals[0].Context) {
		t.Errorf("round-trip mismatch:\n in=%#v\nout=%#v",
			cfg.Identity.Principals[0].Context, cfg2.Identity.Principals[0].Context)
	}
}

func principalContextConfigEmpty(c PrincipalContextConfig) bool {
	return c.Issuer == "" && c.Subject == "" && c.Audience == "" &&
		c.ClientID == "" && c.TenantID == "" && c.Provider == "" &&
		c.Source == "" && c.ExpiresAt == "" && c.ClaimsHash == "" &&
		!c.Verified && len(c.Groups) == 0 && len(c.Scopes) == 0
}
