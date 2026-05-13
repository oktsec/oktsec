package identity

import (
	"strings"
	"testing"
)

func TestValidatePrincipalName_Accepts(t *testing.T) {
	cases := []string{
		"filesystem",
		"github",
		"research-agent",
		"agent_01",
		"org.tool",
		"a",
		"A",
		"0",
		"Z9",
		"claude-code",
		"alice.bob_carol-1",
		"_proxy",
		"_internal-signer_v2",
		strings.Repeat("a", MaxPrincipalNameLen),
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePrincipalName(name); err != nil {
				t.Fatalf("ValidatePrincipalName(%q) returned %v, want nil", name, err)
			}
			if !IsValidPrincipalName(name) {
				t.Fatalf("IsValidPrincipalName(%q) = false, want true", name)
			}
		})
	}
}

func TestValidatePrincipalName_Rejects(t *testing.T) {
	cases := []struct {
		name string
		want string // substring required in the error
	}{
		{"", "empty"},
		{".", "must start with a letter, digit, or underscore"},
		{"..", "must start with a letter, digit, or underscore"},
		{"../evil", "path separator"},
		{"../../pwn", "path separator"},
		{"a/b", "path separator"},
		{`a\b`, "path separator"},
		{"foo\x00bar", "NUL byte"},
		{".hidden", "must start with a letter, digit, or underscore"},
		{"-leading-dash", "must start with a letter, digit, or underscore"},
		{"name with space", "must start with a letter, digit, or underscore"},
		{"weird:char", "must start with a letter, digit, or underscore"},
		{"emoji-✓", "must start with a letter, digit, or underscore"},
		{strings.Repeat("a", MaxPrincipalNameLen+1), "exceeds"},
		{"NUL", "Windows device name"},
		{"nul", "Windows device name"},
		{"CON", "Windows device name"},
		{"con.agent", "Windows device name"},
		{"COM1", "Windows device name"},
		{"lpt9", "Windows device name"},
		{"AUX", "Windows device name"},
		{"PRN", "Windows device name"},
	}
	for _, tc := range cases {
		label := tc.name
		if label == "" {
			label = "<empty>"
		}
		t.Run(label, func(t *testing.T) {
			err := ValidatePrincipalName(tc.name)
			if err == nil {
				t.Fatalf("ValidatePrincipalName(%q) returned nil, want error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidatePrincipalName(%q) error = %q, want substring %q", tc.name, err.Error(), tc.want)
			}
			if IsValidPrincipalName(tc.name) {
				t.Fatalf("IsValidPrincipalName(%q) = true, want false", tc.name)
			}
		})
	}
}

// The _proxy principal signs audit-chain entries from
// internal/proxy/server.go. ValidatePrincipalName must accept it; a
// regression here would silently disable proxy signing on every fresh
// install. See server.go LoadKeypair("_proxy") and
// GenerateKeypair("_proxy") call sites.
func TestValidatePrincipalName_AcceptsReservedProxyPrincipal(t *testing.T) {
	if err := ValidatePrincipalName("_proxy"); err != nil {
		t.Fatalf("ValidatePrincipalName(\"_proxy\") = %v, want nil; audit-chain signing depends on this name", err)
	}
}

// ValidatePublicPrincipalName is the user-facing variant. It must
// refuse internal reserved principals so an external caller (HTTP API,
// dashboard form, SDK consumer, hand-edited config) cannot overwrite
// the _proxy signing key.
func TestValidatePublicPrincipalName_RejectsReserved(t *testing.T) {
	cases := []string{"_proxy", "_internal", "_anything"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePublicPrincipalName(name); err == nil {
				t.Fatalf("ValidatePublicPrincipalName(%q) returned nil; reserved names must be refused on public surfaces", name)
			}
			if !IsReservedPrincipalName(name) {
				t.Fatalf("IsReservedPrincipalName(%q) = false, want true", name)
			}
		})
	}
}

func TestValidatePublicPrincipalName_AcceptsNormalNames(t *testing.T) {
	cases := []string{"filesystem", "github", "research-agent", "agent_01", "org.tool"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePublicPrincipalName(name); err != nil {
				t.Fatalf("ValidatePublicPrincipalName(%q) = %v, want nil", name, err)
			}
		})
	}
}

// Defence in depth: filenames built from a validated principal name must
// never escape a parent directory via filepath.Join semantics. This test
// pins the contract that motivates the validator.
func TestValidatePrincipalName_FilesystemContainment(t *testing.T) {
	const dir = "/tmp/keys"
	bad := []string{"../escape", "../../etc/passwd", `..\windows`, "subdir/leaf"}
	for _, name := range bad {
		if err := ValidatePrincipalName(name); err == nil {
			t.Fatalf("ValidatePrincipalName(%q) accepted a name that would escape %q", name, dir)
		}
	}
}
