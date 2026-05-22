package node

import (
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

func TestPathTail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"/", ""},
		{"file.txt", "file.txt"},
		{"/Users/dev/secret/file.txt", "file.txt"},
		{"/Users/dev/project", "project"},
		{`C:\Users\dev\b.txt`, "b.txt"},
		{`\\share\folder\file.txt`, "file.txt"},
		{"/Users/dev/project/", "project"},
	}
	for _, c := range cases {
		if got := PathTail(c.in); got != c.want {
			t.Errorf("PathTail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHashStringStable(t *testing.T) {
	if HashString("") != "" {
		t.Fatal("empty input should hash to empty string")
	}
	got := HashString("hello")
	if !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("HashString output should be sha256-prefixed, got %q", got)
	}
	if got != HashString("hello") {
		t.Fatal("HashString must be deterministic")
	}
}

func TestURLHostHashRedactsCreds(t *testing.T) {
	in := "https://user:password@example.com/sub?token=abc"
	got := URLHostHash(in)
	if got == "" {
		t.Fatal("URLHostHash returned empty for parsable URL")
	}
	// Must not contain any plaintext from the URL.
	for _, banned := range []string{"user", "password", "sub", "token", "abc", "example.com"} {
		if strings.Contains(got, banned) {
			t.Errorf("URLHostHash leaked %q", banned)
		}
	}
	// Identical hosts (case + creds invariant) must hash equally.
	if URLHostHash("https://EXAMPLE.com") != got {
		t.Errorf("URLHostHash should be case-insensitive on host")
	}
}

func TestCommandTailStripsArgs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/usr/local/bin/npx --secret abc", "npx"},
		{"npx", "npx"},
		{`C:\Users\dev\node.exe`, "node.exe"},
	}
	for _, c := range cases {
		if got := CommandTail(c.in); got != c.want {
			t.Errorf("CommandTail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactMCPServerConfig(t *testing.T) {
	in := config.MCPServerConfig{
		Transport: "stdio",
		Command:   "/usr/bin/npx",
		Args:      []string{"--token", "secret-value", "/Users/dev/path"},
		URL:       "https://user:pw@mcp.example.com/foo?k=v",
		Env:       map[string]string{"SECRET_KEY": "should-not-leak"},
	}
	got := RedactMCPServerConfig("backend", in)
	if got.Name != "backend" || got.Transport != "stdio" {
		t.Fatalf("expected name/transport preserved")
	}
	if got.CommandTail != "npx" {
		t.Errorf("expected command tail npx, got %q", got.CommandTail)
	}
	if got.ArgsCount != 3 {
		t.Errorf("expected args count 3, got %d", got.ArgsCount)
	}
	if got.EnvCount != 1 {
		t.Errorf("expected env count 1, got %d", got.EnvCount)
	}
	// Make sure nothing leaked into the marshalled redaction.
	raw, _ := toJSON(got)
	for _, banned := range []string{"secret-value", "should-not-leak", "pw", "user", "Users", "dev/path"} {
		if strings.Contains(raw, banned) {
			t.Errorf("redacted output leaked %q", banned)
		}
	}
}
