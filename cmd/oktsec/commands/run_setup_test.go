package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/discover"
)

// stubDeps records what autoSetupWithDeps invoked and lets each test override
// individual hooks. Defaults are deliberately strict — anything not opted in
// fails the test.
type stubDeps struct {
	scanResult *discover.Result
	scanErr    error

	hasClaude bool

	connectErr   error
	connectCalls []connectCall

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

func (s *stubDeps) deps() autoSetupDeps {
	return autoSetupDeps{
		scan: func() (*discover.Result, error) {
			if s.scanResult == nil && s.scanErr == nil {
				return &discover.Result{}, nil
			}
			return s.scanResult, s.scanErr
		},
		hasClaudeCLI: func() bool { return s.hasClaude },
		connectClaudeCode: func(port int, endpoint string) error {
			s.connectCalls = append(s.connectCalls, connectCall{port: port, endpoint: endpoint})
			return s.connectErr
		},
		wrapClient: func(client string, opts discover.WrapOpts) (int, error) {
			s.wrapCalls = append(s.wrapCalls, wrapCall{client: client, opts: opts})
			return s.wrapResult, s.wrapErr
		},
	}
}

// scrubKeysDir registers a cleanup that removes any keypair files written for
// the given agent names. It is a defensive net for the non-empty-discovery
// test: if HomeDir() was already memoized to the real user directory before
// the test ran, the agent keypair lands there. We clean up regardless of
// where it lands.
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

// readConfig returns the contents of the generated oktsec.yaml as a string.
func readConfig(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return string(data)
}

// TestAutoSetup_EmptyDiscoveryConnectsClaudeCodeGateway is the direct
// regression test for issue #176. When discovery finds zero MCP servers and
// the `claude` CLI is available, oktsec run must still register the gateway
// and install hooks.
func TestAutoSetup_EmptyDiscoveryConnectsClaudeCodeGateway(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubDeps{hasClaude: true}

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
	got := stub.connectCalls[0]
	if got.port != 9090 {
		t.Errorf("connectClaudeCode port = %d, want 9090", got.port)
	}
	if got.endpoint != "/mcp" {
		t.Errorf("connectClaudeCode endpoint = %q, want %q", got.endpoint, "/mcp")
	}
}

// TestAutoSetup_EmptyDiscoverySkipWrapDoesNotConnectClaudeCode protects the
// --skip-wrap opt-out: even when claude is on PATH, no external client
// configuration should be mutated.
func TestAutoSetup_EmptyDiscoverySkipWrapDoesNotConnectClaudeCode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubDeps{hasClaude: true}

	if err := autoSetupWithDeps(cfgPath, runOpts{skipWrap: true}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatalf(".env not created: %v", err)
	}
	if len(stub.connectCalls) != 0 {
		t.Fatalf("connectClaudeCode called %d time(s) under --skip-wrap, want 0", len(stub.connectCalls))
	}
	if len(stub.wrapCalls) != 0 {
		t.Fatalf("wrapClient called %d time(s) under --skip-wrap, want 0", len(stub.wrapCalls))
	}
}

// TestAutoSetup_EmptyDiscoveryMissingClaudeCLICompletes verifies that
// first-run setup still succeeds when the `claude` CLI is not installed.
// Missing claude is non-fatal: setup completes silently without a connection
// attempt.
func TestAutoSetup_EmptyDiscoveryMissingClaudeCLICompletes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubDeps{hasClaude: false}
	deps := stub.deps()
	deps.connectClaudeCode = func(port int, endpoint string) error {
		t.Fatalf("connectClaudeCode must not be called when claude CLI is missing (got port=%d endpoint=%q)", port, endpoint)
		return nil
	}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, deps); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatalf(".env not created: %v", err)
	}
	if len(stub.connectCalls) != 0 {
		t.Fatalf("connectClaudeCode called %d time(s) without claude CLI, want 0", len(stub.connectCalls))
	}
}

// TestAutoSetup_EmptyDiscoveryClaudeConnectErrorIsNonFatal preserves the
// existing Step 4 behaviour: a `claude mcp add` failure must not abort
// first-run setup.
func TestAutoSetup_EmptyDiscoveryClaudeConnectErrorIsNonFatal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubDeps{
		hasClaude:  true,
		connectErr: errors.New("simulated claude mcp add failure"),
	}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps must not return error when connect fails: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatalf(".env not created: %v", err)
	}
	if got := len(stub.connectCalls); got != 1 {
		t.Fatalf("connectClaudeCode call count = %d, want 1 (must still attempt once)", got)
	}
}

// TestAutoSetup_DiscoveredServersStillConnectClaudeCodeGateway protects the
// non-empty-discovery path. The bug fix routes both paths through the shared
// helper; this test pins the original behaviour so the helper does not
// regress it.
func TestAutoSetup_DiscoveredServersStillConnectClaudeCodeGateway(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	const agent = "okt-test-disc-server"
	scrubKeysDir(t, agent)

	stub := &stubDeps{
		hasClaude:  true,
		wrapResult: 1,
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

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not created: %v", err)
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
		t.Errorf("config missing discovered agent %q in mcp_servers:\n%s", agent, cfgYAML)
	}
}

// TestAutoSetup_EmptyDiscoveryWritesGatewayConfig is a small belt-and-braces
// check that the minimal config still enables the gateway (the gateway must
// be running for Claude Code's HTTP MCP transport to connect).
func TestAutoSetup_EmptyDiscoveryWritesGatewayConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")

	stub := &stubDeps{hasClaude: false}

	if err := autoSetupWithDeps(cfgPath, runOpts{}, stub.deps()); err != nil {
		t.Fatalf("autoSetupWithDeps returned error: %v", err)
	}

	cfgYAML := readConfig(t, cfgPath)
	wantSubstrings := []string{
		"gateway:",
		"enabled: true",
		"port: 9090",
		fmt.Sprintf("endpoint_path: %s", `/mcp`),
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(cfgYAML, s) {
			t.Errorf("minimal config missing %q:\n%s", s, cfgYAML)
		}
	}
}
