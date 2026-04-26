package commands

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"gopkg.in/yaml.v3"
)

// writeMinimalConfigForTokensTest writes a config with the keys-dir field populated
// (config.Save validates that). Tests that need a richer cfg layer their
// own changes on top.
func writeMinimalConfigForTokensTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	cfg := &config.Config{
		Identity: config.IdentityConfig{
			KeysDir: filepath.Join(dir, "keys"),
		},
		Agents: map[string]config.Agent{},
	}
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	return path
}

// captureStdout redirects os.Stdout into a buffer for the duration of
// fn. Used to assert the exact create/revoke output without depending on
// global logger sinks.
func captureStdout(t *testing.T, fn func(*os.File)) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn(w)
	_ = w.Close()
	return <-done
}

// loadTokens reads the persisted tokens for a principal so tests can
// assert on what landed on disk vs what the command claimed to write.
func loadTokens(t *testing.T, path, principalID string) []config.PrincipalTokenConfig {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, p := range cfg.Identity.Principals {
		if p.ID == principalID {
			return p.Tokens
		}
	}
	return nil
}

// 1. create autogenera token-id con sufijo random; el raw token aparece
// una sola vez en stdout y NUNCA termina dentro del config file.
func TestTokensCreate_AutogenIDAndRawTokenNeverPersisted(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	out := captureStdout(t, func(w *os.File) {
		if err := createToken(path, "local-codex", "gateway_bearer", "", "", w); err != nil {
			t.Fatalf("createToken: %v", err)
		}
	})

	if !strings.Contains(out, "Created principal \"local-codex\" with kind=agent.") {
		t.Errorf("output should announce principal auto-creation; got:\n%s", out)
	}
	if !strings.Contains(out, "Raw token (shown once") {
		t.Errorf("output should warn the raw value is shown once; got:\n%s", out)
	}

	// Extract the raw token from stdout and confirm it does NOT appear
	// in the persisted YAML (only the salted hash should).
	rawRe := regexp.MustCompile(`okt_gw_[0-9a-f]+`)
	raw := rawRe.FindString(out)
	if raw == "" {
		t.Fatal("raw gateway token not present in stdout")
	}
	yamlBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(yamlBytes), raw) {
		t.Error("raw token leaked into persisted config")
	}
	if !strings.Contains(string(yamlBytes), "sha256:") {
		t.Error("config does not contain the expected salted hash")
	}

	// Token id must follow the gw-<principal>-<date>-<random> pattern.
	tokens := loadTokens(t, path, "local-codex")
	if len(tokens) != 1 {
		t.Fatalf("want 1 token, got %d", len(tokens))
	}
	idRe := regexp.MustCompile(`^gw-local-codex-\d{4}-\d{2}-\d{2}-[0-9a-f]{6}$`)
	if !idRe.MatchString(tokens[0].ID) {
		t.Errorf("token id %q does not match expected pattern", tokens[0].ID)
	}
}

// 2. Two creates for the same principal on the same day produce
// different ids (the random suffix prevents collision).
func TestTokensCreate_RandomSuffixPreventsCollision(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	for i := 0; i < 2; i++ {
		out := captureStdout(t, func(w *os.File) {
			if err := createToken(path, "local-codex", "gateway_bearer", "", "", w); err != nil {
				t.Fatalf("createToken #%d: %v", i, err)
			}
		})
		_ = out
	}
	tokens := loadTokens(t, path, "local-codex")
	if len(tokens) != 2 {
		t.Fatalf("want 2 tokens, got %d", len(tokens))
	}
	if tokens[0].ID == tokens[1].ID {
		t.Errorf("token ids collided: both %q", tokens[0].ID)
	}
}

// 3. Explicit --token-id duplicate is rejected before any secret
// material is generated. Operator can retry without a partial state.
func TestTokensCreate_DuplicateExplicitIDFails(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	out := captureStdout(t, func(w *os.File) {
		if err := createToken(path, "local-codex", "gateway_bearer", "my-token", "", w); err != nil {
			t.Fatalf("first create: %v", err)
		}
	})
	_ = out
	err := createToken(path, "local-codex", "gateway_bearer", "my-token", "",
		nopWriter(t))
	if err == nil {
		t.Fatal("second create with duplicate id should fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention duplicate; got: %v", err)
	}
}

// 4. Invalid --type fails before touching config (no half-written
// principal, no secret material on disk).
func TestTokensCreate_InvalidTypeFailsCleanly(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	err := createToken(path, "local-codex", "not-a-real-type", "", "", nopWriter(t))
	if err == nil {
		t.Fatal("expected error for unknown token type")
	}
	cfg, _ := config.Load(path)
	if len(cfg.Identity.Principals) != 0 {
		t.Errorf("config should not contain any principal after a failed create; got %d", len(cfg.Identity.Principals))
	}
}

// 5. --expires accepts both Go duration syntax and the d/w/y shortcuts.
// The persisted timestamp is RFC3339 UTC, derived from the supplied
// duration relative to now.
func TestParseExpiry_GoDurationAndDayShortcuts(t *testing.T) {
	now := time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		in       string
		wantTime time.Time
	}{
		{"24h", now.Add(24 * time.Hour)},
		{"90m", now.Add(90 * time.Minute)},
		{"7d", now.Add(7 * 24 * time.Hour)},
		{"30d", now.Add(30 * 24 * time.Hour)},
		{"2w", now.Add(14 * 24 * time.Hour)},
		{"1y", now.Add(365 * 24 * time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseExpiry(tc.in, now)
			if err != nil {
				t.Fatalf("parseExpiry(%q): %v", tc.in, err)
			}
			parsed, err := time.Parse(time.RFC3339, got)
			if err != nil {
				t.Fatalf("output is not RFC3339: %q (%v)", got, err)
			}
			if !parsed.Equal(tc.wantTime) {
				t.Errorf("parseExpiry(%q) = %s, want %s", tc.in, parsed, tc.wantTime)
			}
		})
	}
}

// 6. --expires rejects unparseable input rather than silently writing
// a confusing timestamp.
func TestParseExpiry_RejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "30", "thirty days", "1month", "-5d"} {
		if _, err := parseExpiry(in, time.Now()); err == nil {
			t.Errorf("parseExpiry(%q) should fail", in)
		}
	}
}

// 7. list output never reveals the hash or the raw token. The status
// column reflects expiry/revocation as derived from the persisted
// metadata.
func TestTokensList_NeverPrintsHashOrRaw(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	_ = createToken(path, "local-codex", "gateway_bearer", "active-tok", "", nopWriter(t))
	rawFromCreate := captureStdout(t, func(w *os.File) {
		_ = createToken(path, "local-codex", "gateway_bearer", "second-tok", "", w)
	})
	rawRe := regexp.MustCompile(`okt_gw_[0-9a-f]+`)
	raw := rawRe.FindString(rawFromCreate)
	if raw == "" {
		t.Fatal("could not extract raw from second create")
	}
	// Hand-revoke the second token so list has at least two statuses.
	_ = revokeToken(path, "local-codex", "second-tok", nopWriter(t))

	out := captureStdout(t, func(w *os.File) {
		_ = listTokens(path, "", w)
	})
	if strings.Contains(out, "sha256:") {
		t.Error("list output leaked a hash")
	}
	if strings.Contains(out, raw) {
		t.Error("list output leaked the raw token from create")
	}
	if strings.Contains(out, "okt_gw_") {
		t.Error("list output should never contain a raw-token-shaped value")
	}
	if !strings.Contains(out, "active") {
		t.Error("list should report an active token")
	}
	if !strings.Contains(out, "revoked") {
		t.Error("list should report the revoked token")
	}
}

// 8. revoke sets revoked_at, leaves the token row in place, and a
// second revoke is idempotent.
func TestTokensRevoke_PersistsAndIsIdempotent(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	_ = createToken(path, "local-codex", "gateway_bearer", "tok-1", "", nopWriter(t))
	if err := revokeToken(path, "local-codex", "tok-1", nopWriter(t)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	tokens := loadTokens(t, path, "local-codex")
	if len(tokens) != 1 || tokens[0].RevokedAt == "" {
		t.Fatalf("expected one revoked token, got %+v", tokens)
	}
	if _, err := time.Parse(time.RFC3339, tokens[0].RevokedAt); err != nil {
		t.Errorf("revoked_at not RFC3339: %q", tokens[0].RevokedAt)
	}
	out := captureStdout(t, func(w *os.File) {
		_ = revokeToken(path, "local-codex", "tok-1", w)
	})
	if !strings.Contains(out, "already revoked") {
		t.Errorf("second revoke should be idempotent and announce it; got:\n%s", out)
	}
}

// 9. revoke fails clearly when the principal or token does not exist.
func TestTokensRevoke_NotFoundErrors(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	if err := revokeToken(path, "ghost", "any", nopWriter(t)); err == nil {
		t.Error("revoke should fail when principal does not exist")
	}
	_ = createToken(path, "local-codex", "gateway_bearer", "tok-1", "", nopWriter(t))
	if err := revokeToken(path, "local-codex", "missing", nopWriter(t)); err == nil {
		t.Error("revoke should fail when token id does not exist")
	}
}

// 10. The persisted config round-trips through YAML cleanly; tokens
// keep their fields after a Save/Load cycle.
func TestTokensCreate_ConfigRoundTrip(t *testing.T) {
	path := writeMinimalConfigForTokensTest(t)
	_ = createToken(path, "local-codex", "gateway_bearer", "tok-1", "24h", nopWriter(t))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip config.Config
	if err := yaml.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatalf("yaml round-trip: %v", err)
	}
	if len(roundtrip.Identity.Principals) != 1 || len(roundtrip.Identity.Principals[0].Tokens) != 1 {
		t.Fatalf("round-trip lost data: %+v", roundtrip.Identity.Principals)
	}
	tok := roundtrip.Identity.Principals[0].Tokens[0]
	if tok.ID != "tok-1" || tok.Type != "gateway_bearer" || tok.ExpiresAt == "" || tok.Hash == "" {
		t.Errorf("unexpected token after round-trip: %+v", tok)
	}
}

// nopWriter returns an *os.File pointing at /dev/null, used when a test
// does not care about the printed output.
func nopWriter(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
