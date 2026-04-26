package dashboard

import "testing"

// shellQuotePrincipal is the only thing standing between operator-
// controlled principal ids and a copy-pasteable shell command in
// the coverage drawer. The table below is exhaustive on the
// metacharacter classes a real-world principal id might contain so
// a future "small simplification" cannot accidentally re-introduce
// the unquoted form.
func TestShellQuotePrincipal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain identifier passes through", "local-codex", "local-codex"},
		{"underscores allowed", "team_alpha", "team_alpha"},
		{"dots allowed", "acme.app", "acme.app"},
		{"mixed safe punctuation", "acme.app_v2-prod", "acme.app_v2-prod"},
		{"empty becomes empty quoted slot", "", "''"},
		{"space gets quoted", "team alpha", "'team alpha'"},
		{"semicolon gets quoted", "bad;echo", "'bad;echo'"},
		{"semicolon with spaces", "bad; echo pwned", "'bad; echo pwned'"},
		{"single quote uses POSIX escape", "it's mine", `'it'\''s mine'`},
		{"backtick gets quoted", "x`whoami`", "'x`whoami`'"},
		{"dollar sign gets quoted", "$(id)", "'$(id)'"},
		{"pipe gets quoted", "a|b", "'a|b'"},
		{"ampersand gets quoted", "a&b", "'a&b'"},
		{"newline gets quoted", "a\nb", "'a\nb'"},
		{"slash is not safe (could look like a path)", "a/b", "'a/b'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shellQuotePrincipal(tc.in); got != tc.want {
				t.Errorf("shellQuotePrincipal(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}
