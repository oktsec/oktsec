//go:build examples

// Smoke test for the Startup / Team baseline evidence bundle harness
// (Order 8B.1). It builds the real oktsec binary, runs
// examples/startup-team-baseline/run.sh against a hermetic HOME and config,
// and asserts the bundle contract: required files present, manifest hashes
// match, README boundary language present, no secrets, no identifying paths,
// and no raw key/env/db artifacts copied in.
//
// Behind the `examples` build tag so it stays out of the default `make test`
// (it shells out to bash and compiles the binary). Run via:
//
//	make baseline-bundle-smoke
package commands

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
)

func repoRootForExample(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// cmd/oktsec/commands/<file> -> repo root is three directories up.
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

func writeBundleTestConfig(t *testing.T, path, keysDir, dbPath string) {
	t.Helper()
	cfg := "version: \"1\"\n" +
		"server:\n  port: 8080\n  log_level: info\n" +
		"identity:\n  keys_dir: " + keysDir + "\n  require_signature: false\n" +
		"db_path: " + dbPath + "\n" +
		"agents: {}\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestStartupTeamBaselineBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("harness is a bash script; skipping on windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	root := repoRootForExample(t)
	script := filepath.Join(root, "examples", "startup-team-baseline", "run.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("harness not found: %v", err)
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "oktsec")
	build := exec.Command("go", "build", "-o", bin, "./cmd/oktsec")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build oktsec: %v\n%s", err, out)
	}

	home := filepath.Join(tmp, "home")
	keys := filepath.Join(tmp, "keys")
	for _, d := range []string{home, keys} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(tmp, "oktsec.yaml")
	dbPath := filepath.Join(tmp, "oktsec.db")
	writeBundleTestConfig(t, cfgPath, keys, dbPath)

	bundle := filepath.Join(tmp, "bundle")

	runHarness := func(args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Dir = tmp
		cmd.Env = append(os.Environ(), "HOME="+home, "OKTSEC_BIN="+bin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	runStatus := func(cfg string) (string, error) {
		cmd := exec.Command(bin, "--config", cfg, "status")
		cmd.Dir = tmp
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// --- happy path ---
	if logs, err := runHarness("--config", cfgPath, "--output", bundle); err != nil {
		t.Fatalf("harness failed: %v\n%s", err, logs)
	}

	// Regression (status read-only): the harness must not create or migrate the
	// audit DB. `oktsec status` used to open it writable, which created an empty
	// DB and desynced `node snapshot` (db_available) from `audit` (not created).
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("harness created/left an audit DB at %s; collection must stay read-only", dbPath)
	}

	// Required + generated files must exist. node-status / node-snapshot are
	// best-effort and intentionally excluded from this hard list.
	for _, f := range []string{"README.md", "manifest.json", "audit.json", "audit.sarif", "status.txt", "redactions.json"} {
		if _, err := os.Stat(filepath.Join(bundle, f)); err != nil {
			t.Errorf("missing required file %s: %v", f, err)
		}
	}

	// Manifest parses, has the frozen schema, and every hash matches.
	var man struct {
		Schema string `json:"schema"`
		Files  []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	mb, err := os.ReadFile(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, mb)
	}
	if man.Schema != "oktsec_startup_team_baseline.v1" {
		t.Errorf("manifest schema = %q, want oktsec_startup_team_baseline.v1", man.Schema)
	}
	if len(man.Files) == 0 {
		t.Fatal("manifest lists no files")
	}
	for _, fe := range man.Files {
		data, err := os.ReadFile(filepath.Join(bundle, fe.Path))
		if err != nil {
			t.Errorf("manifest references missing file %s", fe.Path)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != fe.SHA256 {
			t.Errorf("sha256 mismatch for %s: manifest %s, actual %s", fe.Path, fe.SHA256, got)
		}
	}

	// redactions.json must be valid JSON too.
	if rb, err := os.ReadFile(filepath.Join(bundle, "redactions.json")); err != nil {
		t.Errorf("read redactions.json: %v", err)
	} else if !json.Valid(rb) {
		t.Errorf("redactions.json is not valid JSON:\n%s", rb)
	}

	// README boundary language (verbatim from the spec).
	readme, err := os.ReadFile(filepath.Join(bundle, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	for _, phrase := range []string{
		"operational evidence, not a compliance certification",
		"Only routed/configured surfaces are represented",
		"Raw prompts, private keys, secrets and raw audit databases are omitted",
	} {
		if !strings.Contains(string(readme), phrase) {
			t.Errorf("README missing boundary phrase: %q", phrase)
		}
	}

	// Data files: no secrets and no identifying paths.
	forbidden := []string{
		"BEGIN OKTSEC ED25519 PRIVATE KEY",
		"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
		"hooks.slack.com",
	}
	for _, f := range []string{"audit.json", "audit.sarif", "status.txt", "node-status.json", "node-snapshot.json"} {
		data, err := os.ReadFile(filepath.Join(bundle, f))
		if err != nil {
			continue // best-effort files may be absent
		}
		s := string(data)
		for _, bad := range forbidden {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains forbidden token %q", f, bad)
			}
		}
		if strings.Contains(s, home) {
			t.Errorf("%s leaks home path %q", f, home)
		}
		if strings.Contains(s, tmp) {
			t.Errorf("%s leaks unmasked path %q", f, tmp)
		}
	}

	// No raw key/env/db artifacts copied into the bundle.
	entries, err := os.ReadDir(bundle)
	if err != nil {
		t.Fatalf("read bundle dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == ".env" || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".db") || strings.HasSuffix(name, ".pem") {
			t.Errorf("bundle contains forbidden artifact: %s", name)
		}
	}

	// --- overwrite refusal then --force ---
	if logs, err := runHarness("--config", cfgPath, "--output", bundle); err == nil {
		t.Errorf("expected non-zero exit overwriting non-empty dir without --force\n%s", logs)
	}
	if logs, err := runHarness("--config", cfgPath, "--output", bundle, "--force"); err != nil {
		t.Errorf("--force overwrite should succeed: %v\n%s", err, logs)
	}

	// Regression (--force stale files): a pre-existing secret/unexpected file in
	// the target dir must make the bundle fail closed rather than ship silently.
	// Includes a double-dot name (..secret.env) that an earlier glob missed.
	for i, fname := range []string{"old-secret.env", "..secret.env"} {
		stale := filepath.Join(tmp, fmt.Sprintf("bundle-stale-%d", i))
		if err := os.MkdirAll(stale, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stale, fname),
			[]byte("ANTHROPIC_API_KEY=sk-ant-0123456789abcdefghij\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if logs, err := runHarness("--config", cfgPath, "--output", stale, "--force"); err == nil {
			t.Errorf("expected failure with stale file %q in bundle dir\n%s", fname, logs)
		}
	}

	// Regression (strict read-only DB): an existing empty/old DB must not be
	// created, grown, or migrated by collecting status. Pre-create a 0-byte DB
	// and assert its size is unchanged after a run.
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	roOut := filepath.Join(tmp, "bundle-ro")
	if logs, err := runHarness("--config", cfgPath, "--output", roOut); err != nil {
		t.Fatalf("harness failed against empty DB: %v\n%s", err, logs)
	}
	if info, err := os.Stat(dbPath); err != nil {
		t.Errorf("stat dbPath: %v", err)
	} else if info.Size() != 0 {
		t.Errorf("audit DB grew from 0 to %d bytes; collection must be strictly read-only", info.Size())
	}

	// Strict read-only must still READ a populated DB and report its stats
	// without mutating the file (size stable across the run).
	validDB := filepath.Join(tmp, "valid.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	st, err := audit.NewStore(validDB, logger)
	if err != nil {
		t.Fatalf("seed audit DB: %v", err)
	}
	st.Log(audit.Entry{
		ID: "e1", Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "a", ToAgent: "b", ContentHash: "deadbeef",
		Status: "delivered", PolicyDecision: "clean",
	})
	st.Flush()
	if err := st.Close(); err != nil {
		t.Fatalf("close seed DB: %v", err)
	}
	infoBefore, err := os.Stat(validDB)
	if err != nil {
		t.Fatalf("stat seeded DB: %v", err)
	}
	sizeBefore := infoBefore.Size()
	validCfg := filepath.Join(tmp, "oktsec-valid.yaml")
	writeBundleTestConfig(t, validCfg, keys, validDB)
	validOut := filepath.Join(tmp, "bundle-valid")
	if logs, err := runHarness("--config", validCfg, "--output", validOut); err != nil {
		t.Fatalf("harness failed against populated DB: %v\n%s", err, logs)
	}
	if info, err := os.Stat(validDB); err != nil {
		t.Errorf("stat populated DB: %v", err)
	} else if info.Size() != sizeBefore {
		t.Errorf("populated audit DB changed size %d -> %d under strict read-only", sizeBefore, info.Size())
	}
	if data, err := os.ReadFile(filepath.Join(validOut, "status.txt")); err != nil {
		t.Errorf("read status.txt: %v", err)
	} else if !strings.Contains(string(data), "Total msgs:") {
		t.Errorf("status.txt missing message stats for a populated DB:\n%s", data)
	}

	// Regression (legacy DB must not under-report): a DB with rows but missing
	// the newer columns the query selects must report stats as unavailable, not
	// silently print zero counts. Strict read-only skips migrations, so the
	// query errors instead of materializing the columns.
	legacyDB := filepath.Join(tmp, "legacy.db")
	seedLegacyAuditDB(t, legacyDB)
	legacyBefore, err := os.Stat(legacyDB)
	if err != nil {
		t.Fatalf("stat legacy DB: %v", err)
	}
	legacyCfg := filepath.Join(tmp, "oktsec-legacy.yaml")
	writeBundleTestConfig(t, legacyCfg, keys, legacyDB)
	legacyOut := filepath.Join(tmp, "bundle-legacy")
	if logs, err := runHarness("--config", legacyCfg, "--output", legacyOut); err != nil {
		t.Fatalf("harness failed against legacy DB: %v\n%s", err, logs)
	}
	if info, err := os.Stat(legacyDB); err != nil {
		t.Errorf("stat legacy DB after run: %v", err)
	} else if info.Size() != legacyBefore.Size() {
		t.Errorf("legacy DB changed size %d -> %d; must not migrate under strict read-only", legacyBefore.Size(), info.Size())
	}
	if data, err := os.ReadFile(filepath.Join(legacyOut, "status.txt")); err != nil {
		t.Errorf("read legacy status.txt: %v", err)
	} else {
		s := string(data)
		if strings.Contains(s, "Total msgs:    0") {
			t.Errorf("legacy DB with rows was under-reported as zero:\n%s", s)
		}
		if !strings.Contains(s, "unavailable") {
			t.Errorf("legacy DB stats should be reported unavailable, not silently dropped:\n%s", s)
		}
	}

	// Regression (unopenable DB recorded, not hidden): a db_path whose parent is
	// a regular file makes os.Stat fail with a non-IsNotExist error. status must
	// report it as unavailable rather than silently omitting the audit section.
	notDir := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badCfg := filepath.Join(tmp, "oktsec-baddb.yaml")
	writeBundleTestConfig(t, badCfg, keys, filepath.Join(notDir, "oktsec.db"))
	if out, err := runStatus(badCfg); err != nil {
		t.Errorf("status should exit 0 even with an unopenable DB: %v\n%s", err, out)
	} else if !strings.Contains(out, "Audit stats:   unavailable") {
		t.Errorf("status must record an unopenable DB as unavailable, not hide it:\n%s", out)
	}

	// Regression (secret scan coverage): exercise the harness's own SECRET_PAT
	// against known token shapes and benign text, so it stays fail-closed for
	// real tokens without flagging diagnostic env-var names.
	pat := extractSecretPat(t, script)
	for _, p := range []string{
		"node server.js --token ghp_0123456789012345678901",
		"AKIA0123456789ABCDEF",
		"--key sk-ant-0123456789abcdefghij",
		"glpat-0123456789abcdefghij",
		"GITHUB_TOKEN=ghp_x",
		"-----BEGIN OKTSEC ED25519 PRIVATE KEY-----",
	} {
		if !grepMatchesPattern(t, pat, p) {
			t.Errorf("SECRET_PAT should match secret value %q", p)
		}
	}
	for _, n := range []string{
		"No agents registered",
		`has env var "ANTHROPIC_API_KEY" which appears to contain a secret`,
		"Health: 80/100 (B)",
		"node_id: sha256:abcdef0123456789abcdef0123456789",
	} {
		if grepMatchesPattern(t, pat, n) {
			t.Errorf("SECRET_PAT should NOT match benign text %q", n)
		}
	}
}

// extractSecretPat pulls the canonical SECRET_PAT one-liner out of run.sh so
// the test exercises the exact pattern the harness uses (no parallel copy to
// drift from).
func extractSecretPat(t *testing.T, script string) string {
	t.Helper()
	data, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read harness: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		const prefix = "SECRET_PAT='"
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, "'") {
			return line[len(prefix) : len(line)-1]
		}
	}
	t.Fatal("could not find SECRET_PAT in harness")
	return ""
}

// seedLegacyAuditDB writes a minimal pre-migration audit_log: it has the
// original columns and one delivered row but lacks the newer columns the
// current query selects. Opened strictly read-only (no migration), the query
// errors — exactly the legacy case the status command must not under-report.
func seedLegacyAuditDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy DB: %v", err)
	}
	defer func() { _ = db.Close() }()
	const legacySchema = `CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		from_agent TEXT NOT NULL,
		to_agent TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		signature_verified INTEGER,
		pubkey_fingerprint TEXT,
		status TEXT NOT NULL,
		rules_triggered TEXT,
		policy_decision TEXT NOT NULL,
		latency_ms INTEGER
	);`
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_log (id, timestamp, from_agent, to_agent, content_hash, status, policy_decision)`+
			` VALUES ('e1', ?, 'a', 'b', 'deadbeef', 'delivered', 'clean')`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
}

// grepMatchesPattern reports whether grep -E pat matches s, using the same grep
// the harness relies on.
func grepMatchesPattern(t *testing.T, pat, s string) bool {
	t.Helper()
	cmd := exec.Command("grep", "-Eq", pat)
	cmd.Stdin = strings.NewReader(s + "\n")
	err := cmd.Run()
	if err == nil {
		return true
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false // grep: no match
	}
	t.Fatalf("grep failed for pattern: %v", err)
	return false
}
