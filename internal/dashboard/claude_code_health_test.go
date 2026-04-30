package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

// TestClaudeCodeHealthEndpoint_NotInstalled verifies the dashboard
// reports the right status string when no Claude state exists. The
// dashboard pill code in Phase 4 will read this verbatim, so locking
// it in here prevents accidental copy drift later.
func TestClaudeCodeHealthEndpoint_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Point HOME at an empty temp dir so the connector inspector sees
	// a clean machine. PATH is cleared so the host's real `claude`
	// binary (if any) does not flip Detected to true.
	emptyHome := t.TempDir()
	t.Setenv("HOME", emptyHome)
	t.Setenv("PATH", "")

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dir, "test.db"),
		Agents:  map[string]config.Agent{},
	}
	srv := NewServer(cfg, filepath.Join(dir, "oktsec.yaml"), store, identity.NewKeyStore(), sharedScanner, logger)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Use ?project=<empty-temp-dir> so the handler does not pick up
	// this repo's project state by accident.
	u := "/dashboard/api/connectors/claude-code/health?" + url.Values{"project": {emptyHome}}.Encode()
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		Inventory struct {
			Detected bool `json:"detected"`
		} `json:"inventory"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v; body=%s", err, w.Body.String())
	}
	if body.Health.Status != "not_installed" {
		t.Errorf("status = %q, want not_installed (body=%s)", body.Health.Status, w.Body.String())
	}
	if body.Inventory.Detected {
		t.Error("inventory.Detected should be false on an empty home")
	}
}

// newProjectValidationServer builds a Server suitable for the
// project-dir validation tests below. Each test owns its own home
// tempdir + config tempdir so the allowed-root set is fully under
// test control, with no leakage from the host's real HOME or this
// repo's working tree.
func newProjectValidationServer(t *testing.T) (*Server, http.Handler, *http.Cookie, string, string) {
	t.Helper()
	homeDir := t.TempDir()
	cfgDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("PATH", "")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	dbDir := t.TempDir()
	store, err := audit.NewStore(filepath.Join(dbDir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dbDir, "test.db"),
		Agents:  map[string]config.Agent{},
	}
	srv := NewServer(cfg, filepath.Join(cfgDir, "oktsec.yaml"), store, identity.NewKeyStore(), sharedScanner, logger)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	return srv, handler, cookie, homeDir, cfgDir
}

// projectHealthRequest issues a GET against the Claude Code health
// endpoint with a configurable ?project= value. Pass an empty
// string to omit the query param entirely so the handler exercises
// its blank-input fallback.
func projectHealthRequest(t *testing.T, handler http.Handler, cookie *http.Cookie, project string) *httptest.ResponseRecorder {
	t.Helper()
	u := "/dashboard/api/connectors/claude-code/health"
	if project != "" {
		u += "?" + url.Values{"project": {project}}.Encode()
	}
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// TestClaudeCodeHealth_RejectsTraversal — ?project=../../etc must
// be rejected as relative input. Even a string that "looks
// absolute after Clean" is not absolute up front, and the handler
// must refuse it before any os.Stat / EvalSymlinks runs.
func TestClaudeCodeHealth_RejectsTraversal(t *testing.T) {
	_, handler, cookie, _, _ := newProjectValidationServer(t)
	w := projectHealthRequest(t, handler, cookie, "../../etc")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "absolute") {
		t.Errorf("400 body should explain the absolute-path rule; got %q", w.Body.String())
	}
}

// TestClaudeCodeHealth_RejectsRelativeProject — a clearly
// relative path with no traversal pieces is still rejected.
// Relative input from HTTP is ambiguous; the operator must be
// explicit.
func TestClaudeCodeHealth_RejectsRelativeProject(t *testing.T) {
	_, handler, cookie, _, _ := newProjectValidationServer(t)
	w := projectHealthRequest(t, handler, cookie, "relative/project")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestClaudeCodeHealth_RejectsAbsoluteOutsideAllowedRoot — an
// absolute, existing directory that lives outside both the home
// tempdir and the config tempdir must be refused.
func TestClaudeCodeHealth_RejectsAbsoluteOutsideAllowedRoot(t *testing.T) {
	_, handler, cookie, _, _ := newProjectValidationServer(t)
	outside := t.TempDir() // a fresh tempdir, not inside HOME or cfgDir
	w := projectHealthRequest(t, handler, cookie, outside)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "outside allowed roots") {
		t.Errorf("400 body should name the root-membership rule; got %q", w.Body.String())
	}
}

// TestClaudeCodeHealth_RejectsSymlinkEscape — a symlink that
// lives inside the config dir but resolves to a directory outside
// every allowed root must be refused. The EvalSymlinks step is
// what closes this gap; without it, HasPrefix-style checks would
// pass because the input string starts inside cfgDir.
func TestClaudeCodeHealth_RejectsSymlinkEscape(t *testing.T) {
	_, handler, cookie, _, cfgDir := newProjectValidationServer(t)
	outside := t.TempDir() // outside HOME and cfgDir
	link := filepath.Join(cfgDir, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	w := projectHealthRequest(t, handler, cookie, link)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "outside allowed roots") {
		t.Errorf("400 body should name the root-membership rule; got %q", w.Body.String())
	}
}

// TestClaudeCodeHealth_AcceptsProjectInsideConfigDir — the happy
// path: a real subdirectory of the loaded config dir is accepted,
// and the inventory.current_project_path the connector returns is
// the EvalSymlinks-resolved canonical form (NOT the raw input
// string), so any downstream consumer that joins paths off it
// keeps working from a stable base.
func TestClaudeCodeHealth_AcceptsProjectInsideConfigDir(t *testing.T) {
	_, handler, cookie, _, cfgDir := newProjectValidationServer(t)
	subdir := filepath.Join(cfgDir, "myproject")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	w := projectHealthRequest(t, handler, cookie, subdir)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Inventory struct {
			CurrentProjectPath string `json:"current_project_path"`
		} `json:"inventory"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	canonical, err := filepath.EvalSymlinks(subdir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if body.Inventory.CurrentProjectPath != canonical {
		t.Errorf("current_project_path = %q, want canonical %q",
			body.Inventory.CurrentProjectPath, canonical)
	}
}

// TestClaudeCodeHealth_DefaultsToConfigDirWhenProjectOmitted — no
// query param at all keeps the pre-existing behavior: the handler
// uses filepath.Dir(s.cfgPath) as the implicit project. The
// validation helper must NOT re-validate that operator-trusted
// path, so this test asserts the endpoint still returns 200.
func TestClaudeCodeHealth_DefaultsToConfigDirWhenProjectOmitted(t *testing.T) {
	_, handler, cookie, _, _ := newProjectValidationServer(t)
	w := projectHealthRequest(t, handler, cookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestClaudeCodeHealth_RejectsAbsoluteMissingPathOutsideRoot — an
// absolute path that does NOT exist and is also outside every
// allowed root must surface as "outside allowed roots", not as
// "path not accessible". The earlier ordering (Stat first,
// root-check after) leaked filesystem existence: missing-outside
// returned the os error wording, existing-outside returned the
// root-check wording. The lexical pre-check collapses both into
// the same uniform refusal so an authenticated dashboard user
// cannot use the endpoint to probe arbitrary filesystem paths.
func TestClaudeCodeHealth_RejectsAbsoluteMissingPathOutsideRoot(t *testing.T) {
	_, handler, cookie, _, _ := newProjectValidationServer(t)
	missing := "/this-path-should-not-exist-anywhere/oktsec-test-12345"
	w := projectHealthRequest(t, handler, cookie, missing)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "outside allowed roots") {
		t.Errorf("400 body must say 'outside allowed roots' (no FS probe leak); got %q", body)
	}
	// Negative assertion: a leaky path would have surfaced as the
	// stat error wording, which the helper used to forward as
	// "path not accessible".
	if strings.Contains(body, "path not accessible") {
		t.Errorf("body leaked filesystem state: %q", body)
	}
}

// TestClaudeCodeHealth_RejectsFileInsideAllowedRoot — a regular
// file (not a directory) that lives inside an allowed root reaches
// the IsDir check and is refused with the "not a directory"
// message. Documents that the FS probes only run after the lexical
// gate has accepted the path.
func TestClaudeCodeHealth_RejectsFileInsideAllowedRoot(t *testing.T) {
	_, handler, cookie, _, cfgDir := newProjectValidationServer(t)
	f := filepath.Join(cfgDir, "not-a-dir.txt")
	if err := os.WriteFile(f, []byte("oktsec"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	w := projectHealthRequest(t, handler, cookie, f)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not a directory") {
		t.Errorf("400 body should say 'not a directory'; got %q", w.Body.String())
	}
}

// TestClaudeCodeHealth_AcceptsDoubleDotPrefixedDirectory — a
// directory whose name happens to start with the two dot bytes
// (e.g. "..project") is a perfectly valid POSIX name and must be
// accepted when it lives inside an allowed root. A naive
// HasPrefix(rel, "..") check would mis-classify it as traversal
// and produce a false-positive 400.
func TestClaudeCodeHealth_AcceptsDoubleDotPrefixedDirectory(t *testing.T) {
	_, handler, cookie, _, cfgDir := newProjectValidationServer(t)
	weird := filepath.Join(cfgDir, "..project")
	if err := os.MkdirAll(weird, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	w := projectHealthRequest(t, handler, cookie, weird)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}
