package dashboard

import (
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// runtime_posture_identity_context_test.go covers Phase 4E-0 posture
// behavior: the identity_context dimension must surface the mapped
// state when any configured Principal carries a non-empty context,
// keep saying "External identity context not configured" otherwise,
// stay silent on vendor names, and never let context promote a
// signature-disabled state to OK.

func principalsWithContext() []config.PrincipalConfig {
	return []config.PrincipalConfig{{
		ID:          "claude-code",
		DisplayName: "Claude Code",
		Kind:        "agent",
		WorkspaceID: "local",
		Context: config.PrincipalContextConfig{
			Issuer:   "https://issuer.example.com/",
			Subject:  "agent/claude-code",
			Audience: "oktsec",
			Provider: "custom_oidc",
			Source:   "static_config",
			Verified: true,
		},
	}}
}

// TestRuntimePosture_IdentityContextMappedWithSignature — sig
// required + context present -> OK + "external context mapped".
func TestRuntimePosture_IdentityContextMappedWithSignature(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.Identity.RequireSignature = true
	in.Cfg.Identity.Principals = principalsWithContext()

	snap := buildRuntimePostureSnapshot(in)
	id := findDimension(t, snap, PostureDimIdentityContext)

	if id.Status != PostureCellOK {
		t.Errorf("Status = %q, want ok", id.Status)
	}
	if !strings.Contains(strings.ToLower(id.Summary), "external context mapped") {
		t.Errorf("Summary should advertise mapped context: %q", id.Summary)
	}
	if strings.Contains(strings.ToLower(id.Summary), "not configured") {
		t.Errorf("Summary still says not configured even though context is mapped: %q", id.Summary)
	}
	for _, vendor := range []string{"okta", "auth0", "entra"} {
		if strings.Contains(strings.ToLower(id.Summary+id.Evidence), vendor) {
			t.Errorf("identity_context mentions vendor %q: summary=%q evidence=%q", vendor, id.Summary, id.Evidence)
		}
	}
}

// TestRuntimePosture_IdentityContextMappedWithDelegation — sig + ctx
// + delegation -> single-line summary that names all three.
func TestRuntimePosture_IdentityContextMappedWithDelegation(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.Identity.RequireSignature = true
	in.Identity.RequireDelegation = true
	in.Cfg.Identity.Principals = principalsWithContext()

	snap := buildRuntimePostureSnapshot(in)
	id := findDimension(t, snap, PostureDimIdentityContext)

	if id.Status != PostureCellOK {
		t.Errorf("Status = %q, want ok", id.Status)
	}
	for _, want := range []string{"signed", "delegation", "external context mapped"} {
		if !strings.Contains(strings.ToLower(id.Summary), want) {
			t.Errorf("Summary missing %q: %q", want, id.Summary)
		}
	}
}

// TestRuntimePosture_IdentityContextMappedWithoutDelegationCallsItOut —
// when context is present but delegation is not enforced, the page
// should not silently imply delegation is active. The summary must
// say "Delegation not enforced." so the operator sees the gap.
func TestRuntimePosture_IdentityContextMappedWithoutDelegationCallsItOut(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.Identity.RequireSignature = true
	in.Identity.RequireDelegation = false
	in.Cfg.Identity.Principals = principalsWithContext()

	snap := buildRuntimePostureSnapshot(in)
	id := findDimension(t, snap, PostureDimIdentityContext)

	if !strings.Contains(strings.ToLower(id.Summary), "delegation not enforced") {
		t.Errorf("Summary should call out missing delegation: %q", id.Summary)
	}
}

// TestRuntimePosture_IdentityContextAbsentSaysNotConfigured — sig
// required + no context -> existing local-signed copy plus the new
// "External identity context not configured." trailer.
func TestRuntimePosture_IdentityContextAbsentSaysNotConfigured(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.Identity.RequireSignature = true
	// in.Cfg has no principals -> no context mapped

	snap := buildRuntimePostureSnapshot(in)
	id := findDimension(t, snap, PostureDimIdentityContext)

	if id.Status != PostureCellOK {
		t.Errorf("Status = %q, want ok", id.Status)
	}
	if !strings.Contains(strings.ToLower(id.Summary), "local signed identity required") {
		t.Errorf("Summary missing local signed copy: %q", id.Summary)
	}
	if !strings.Contains(strings.ToLower(id.Summary), "external identity context not configured") {
		t.Errorf("Summary missing 'not configured' trailer: %q", id.Summary)
	}
}

// TestRuntimePosture_SignatureDisabledStillWarnsEvenWithContext —
// context never promotes the dimension when signature is off. The
// page must keep the warning so the operator sees the gating issue.
func TestRuntimePosture_SignatureDisabledStillWarnsEvenWithContext(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.Identity.RequireSignature = false
	in.Cfg.Identity.Principals = principalsWithContext()

	snap := buildRuntimePostureSnapshot(in)
	id := findDimension(t, snap, PostureDimIdentityContext)

	if id.Status != PostureCellWarn {
		t.Errorf("Status = %q, want warn (context cannot promote sig-disabled state)", id.Status)
	}
	if !strings.Contains(strings.ToLower(id.Summary), "signature is not required") {
		t.Errorf("Summary changed away from signature-disabled warning: %q", id.Summary)
	}
}
