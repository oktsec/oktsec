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
		{".", "must start with a letter or digit"},
		{"..", "must start with a letter or digit"},
		{"../evil", "path separator"},
		{"../../pwn", "path separator"},
		{"a/b", "path separator"},
		{`a\b`, "path separator"},
		{"foo\x00bar", "NUL byte"},
		{".hidden", "must start with a letter or digit"},
		{"-leading-dash", "must start with a letter or digit"},
		{"_leading_underscore", "must start with a letter or digit"},
		{"name with space", "must start with a letter or digit"},
		{"weird:char", "must start with a letter or digit"},
		{"emoji-✓", "must start with a letter or digit"},
		{strings.Repeat("a", MaxPrincipalNameLen+1), "exceeds"},
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
