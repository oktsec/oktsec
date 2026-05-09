package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors/claudecode"
	"github.com/oktsec/oktsec/internal/discover"
)

// stubAutoSetupDeps records what autoSetupWithDeps invoked. The Claude
// Code lifecycle is collapsed into a single connectClaudeCode callback
// that returns a claudeCodeLifecycleResult, mirroring how the helper
// behaves in production. wrapClient is recorded the same way.
type stubAutoSetupDeps struct {
	scanResult *discover.Result
	scanErr    error

	// connectResult / connectErr are returned by the connectClaudeCode
	// stub. Tests that want to simulate a missing CLI leave both at
	// their zero values (no GatewayAttempted, no HooksAttempted).
	connectResult claudeCodeLifecycleResult
	connectErr    error
	connectCalls  []connectCall

	wrapResult int
	wrapErr    error
	wrapCalls  []wrapCall
}

type connectCall struct {
	port     int
	endpoint string
}

type wrapCall struct {
	client string
	opts   discover.WrapOpts
}

func (s *stubAutoSetupDeps) deps() autoSetupDeps {
	return autoSetupDeps{
		scan: func() (*discover.Result, error) {
			if s.scanResult == nil && s.scanErr == nil {
				return &discover.Result{}, nil
			}
			return s.scanResult, s.scanErr
		},
		connectClaudeCode: func(ctx context.Context, port int, endpoint string) (claudeCodeLifecycleResult, error) {
			s.connectCalls = append(s.connectCalls, connectCall{port: port, endpoint: endpoint})
			return s.connectResult, s.connectErr
		},
		wrapClient: func(client string, opts discover.WrapOpts) (int, error) {
			s.wrapCalls = append(s.wrapCalls, wrapCall{client: client, opts: opts})
			return s.wrapResult, s.wrapErr
		},
	}
}

// scrubKeysDir registers a cleanup that removes any keypair files written for
// the given agent names. Defensive net for the non-empty discovery test in
// case config.HomeDir() was already memoized to the real user directory.
func scrubKeysDir(t *testing.T, agents ...string) {
	t.Helper()
	keysDir := config.DefaultKeysDir()
	t.Cleanup(func() {
		for _, name := range agents {
			_ = os.Remove(filepath.Join(keysDir, name+".priv"))
			_ = os.Remove(filepath.Join(keysDir, name+".pub"))
		}
	})
}

func readConfig(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return string(data)
}

// connectedResult builds a stub lifecycle result that mirrors a successful
// connect: gateway entry was added and the hook manifest was installed.
func connectedResult() claudeCodeLifecycleResult {
	plan := []claudecode.PlannedHookEntry{{Event: "PreToolUse"}}
	return claudeCodeLifecycleResult{
		GatewayAttempted: true,
		GatewayOK:        true,
		HooksAttempted:   true,
		HooksOK:          true,
		InstallResult: &claudecode.InstallResult{
			SettingsPath: "/tmp/fake-settings.json",
			Plan:         plan,
			Wrote:        true,
		},
	}
}

// TestAutoSetup_EmptyDiscoveryConnectsClaudeCodeGatewayAndHooks is the
// regression test for issue #176 plus the Phase 4F-0 contract: zero-discovery
// first-run setup must register the gateway entry AND install the V2 hook
// manifest when claude is available.
func TestAutoSetup_EmptyDiscoveryConnectsClaudeCodeGatewayAndHooks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubAutoSetupDeps{connectResult: connectedResult()}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatalf(".env not created: %v", err)
	}
	if got := len(stub.connectCalls); got != 1 {
		t.Fatalf("connectClaudeCode call count = %d, want 1", got)
	}
	if got := stub.connectCalls[0]; got.port != 9090 || got.endpoint != "/mcp" {
		t.Errorf("connectClaudeCode called with port=%d endpoint=%q, want 9090 /mcp", got.port, got.endpoint)
	}
}

// TestAutoSetup_EmptyDiscoveryHookFailureIsNonFatal pins the best-effort
// contract for `oktsec run`: a hook install failure must not abort first-run
// setup, but it must still surface as a partial state in the result.
func TestAutoSetup_EmptyDiscoveryHookFailureIsNonFatal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	partial := claudeCodeLifecycleResult{
		GatewayAttempted: true,
		GatewayOK:        true,
		HooksAttempted:   true,
		HooksOK:          false,
		HooksErr:         errors.New("simulated hook install failure"),
		Warnings:         []string{"hook install: simulated hook install failure"},
	}
	stub := &stubAutoSetupDeps{connectResult: partial}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps must not return error when hook install fails: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
	}
	if got := len(stub.connectCalls); got != 1 {
		t.Fatalf("connectClaudeCode call count = %d, want 1", got)
	}
	if !partial.Partial() {
		t.Fatalf("partial fixture must report Partial() = true")
	}
	if len(stub.wrapCalls) != 0 {
		t.Errorf("wrapClient must not be called for empty discovery, got %d calls", len(stub.wrapCalls))
	}
}

// TestAutoSetup_SkipWrapSkipsGatewayAndHooks pins the --skip-wrap opt-out:
// no gateway, no hooks, no stdio wrap, even when the lifecycle helper would
// otherwise have something to do.
func TestAutoSetup_SkipWrapSkipsGatewayAndHooks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubAutoSetupDeps{connectResult: connectedResult()}

	if err := autoSetupWithDeps(cfgPath, runOpts{skipWrap: true}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	if len(stub.connectCalls) != 0 {
		t.Errorf("connectClaudeCode called %d time(s) under --skip-wrap, want 0", len(stub.connectCalls))
	}
	if len(stub.wrapCalls) != 0 {
		t.Errorf("wrapClient called %d time(s) under --skip-wrap, want 0", len(stub.wrapCalls))
	}
}

// TestAutoSetup_EmptyDiscoveryMissingClaudeCLICompletes verifies missing
// claude CLI stays non-fatal. The lifecycle helper returns a result with
// nothing attempted; the run code path keeps going.
func TestAutoSetup_EmptyDiscoveryMissingClaudeCLICompletes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	missingCLI := claudeCodeLifecycleResult{
		Warnings: []string{"claude CLI not found on PATH; install Claude Code or run `claude --version`"},
	}
	stub := &stubAutoSetupDeps{connectResult: missingCLI}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}
	if got := len(stub.connectCalls); got != 1 {
		t.Fatalf("connectClaudeCode call count = %d, want 1 (must still attempt)", got)
	}
}

// TestAutoSetup_EmptyDiscoveryClaudeConnectErrorIsNonFatal preserves the
// existing best-effort contract: a connect error returned to the caller
// (rare path, since the helper normally swallows best-effort errors as
// warnings) must not abort first-run setup.
func TestAutoSetup_EmptyDiscoveryClaudeConnectErrorIsNonFatal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubAutoSetupDeps{
		connectErr: errors.New("simulated lifecycle error"),
	}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps must not return error when lifecycle fails: %v", err)
	}
	if got := len(stub.connectCalls); got != 1 {
		t.Fatalf("connectClaudeCode call count = %d, want 1 (must still attempt once)", got)
	}
}

// TestAutoSetup_DiscoveredServersUseSameClaudeLifecycle protects the
// non-empty discovery path. Both paths must share the lifecycle helper:
// gateway + V2 hooks for Claude Code, stdio wrapping for other clients.
func TestAutoSetup_DiscoveredServersUseSameClaudeLifecycle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	const agent = "okt-test-disc-server"
	scrubKeysDir(t, agent)

	stub := &stubAutoSetupDeps{
		connectResult: connectedResult(),
		wrapResult:    1,
		scanResult: &discover.Result{
			Clients: []discover.ClientResult{
				{
					Client: "cursor",
					Path:   "/fake/cursor.json",
					Servers: []discover.MCPServer{
						{Name: agent, Command: "/bin/echo", Args: []string{"hi"}},
					},
				},
			},
		},
	}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	if got := len(stub.connectCalls); got != 1 {
		t.Fatalf("connectClaudeCode call count = %d, want 1", got)
	}
	if got := len(stub.wrapCalls); got != 1 {
		t.Fatalf("wrapClient call count = %d, want 1", got)
	}
	if stub.wrapCalls[0].client != "cursor" {
		t.Errorf("wrapClient called with client = %q, want cursor", stub.wrapCalls[0].client)
	}

	cfgYAML := readConfig(t, cfgPath)
	if !strings.Contains(cfgYAML, "mcp_servers:") {
		t.Errorf("config missing mcp_servers block:\n%s", cfgYAML)
	}
	if !strings.Contains(cfgYAML, agent) {
		t.Errorf("config missing discovered agent %q:\n%s", agent, cfgYAML)
	}
}

// TestAutoSetup_EmptyDiscoveryWritesGatewayConfig is a small belt-and-braces
// check that the minimal config still enables the gateway. The gateway must
// be running for Claude Code's HTTP MCP transport to connect.
func TestAutoSetup_EmptyDiscoveryWritesGatewayConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubAutoSetupDeps{}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	cfgYAML := readConfig(t, cfgPath)
	want := []string{"gateway:", "enabled: true", "port: 9090", fmt.Sprintf("endpoint_path: %s", `/mcp`)}
	for _, s := range want {
		if !strings.Contains(cfgYAML, s) {
			t.Errorf("minimal config missing %q:\n%s", s, cfgYAML)
		}
	}
}

// TestRunClaudeCodeUsesManifestV2Installer pins the V2 manifest parity
// invariant: when the default lifecycle deps are wired to the real
// claudecode.InstallV2 against a temp HOME, the resulting settings.json
// carries the V2 manifest marker. This test fails if any future change
// reintroduces a hand-written PreToolUse/PostToolUse-only writer.
func TestRunClaudeCodeUsesManifestV2Installer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	deps := claudeCodeLifecycleDeps{
		// Pretend claude is available and that `claude mcp add` succeeds.
		hasClaudeCLI: func() bool { return true },
		runMCPAdd: func(ctx context.Context, port int, endpoint string) ([]byte, error) {
			return []byte("ok"), nil
		},
		runMCPRemove: func(ctx context.Context) ([]byte, error) {
			return []byte("ok"), nil
		},
		// Use the real installer so we exercise the V2 manifest writer.
		installHooksV2:   claudecode.InstallV2,
		uninstallHooksV2: claudecode.UninstallV2,
		executable: func() (string, error) {
			return "/usr/local/bin/oktsec", nil
		},
	}

	res, err := connectClaudeCodeRuntime(context.Background(),
		claudeCodeConnectOptions{Port: 9090, Endpoint: "/mcp", Mode: claudeConnectStrict},
		deps)
	if err != nil {
		t.Fatalf("connectClaudeCodeRuntime: %v", err)
	}
	if !res.HooksOK {
		t.Fatalf("hooks did not install successfully: %+v", res)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	body, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(body), claudecode.ManifestV2Marker) {
		t.Errorf("expected ManifestV2Marker %q in settings.json:\n%s",
			claudecode.ManifestV2Marker, string(body))
	}
}
