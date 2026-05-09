package commands

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/connectors/claudecode"
)

// stubLifecycleDeps records every external call the lifecycle helper
// would make. Each callback can be overridden per test. Defaults match
// the happy path: claude is on PATH, gateway add succeeds, install /
// uninstall succeed.
type stubLifecycleDeps struct {
	hasCLI bool

	addCalls    int
	addOut      []byte
	addErr      error
	addSeenPort int
	addSeenEP   string

	removeCalls int
	removeOut   []byte
	removeErr   error

	installCalls   int
	installResult  claudecode.InstallResult
	installErr     error
	installSeenOpt claudecode.InstallOptions

	uninstallCalls   int
	uninstallResult  claudecode.UninstallResult
	uninstallErr     error
	uninstallSeenOpt claudecode.UninstallOptions

	exePath string
	exeErr  error
}

func (s *stubLifecycleDeps) deps() claudeCodeLifecycleDeps {
	return claudeCodeLifecycleDeps{
		hasClaudeCLI: func() bool { return s.hasCLI },
		runMCPAdd: func(ctx context.Context, port int, endpoint string) ([]byte, error) {
			s.addCalls++
			s.addSeenPort = port
			s.addSeenEP = endpoint
			return s.addOut, s.addErr
		},
		runMCPRemove: func(ctx context.Context) ([]byte, error) {
			s.removeCalls++
			return s.removeOut, s.removeErr
		},
		installHooksV2: func(ctx context.Context, opts claudecode.InstallOptions) (claudecode.InstallResult, error) {
			s.installCalls++
			s.installSeenOpt = opts
			return s.installResult, s.installErr
		},
		uninstallHooksV2: func(ctx context.Context, opts claudecode.UninstallOptions) (claudecode.UninstallResult, error) {
			s.uninstallCalls++
			s.uninstallSeenOpt = opts
			return s.uninstallResult, s.uninstallErr
		},
		executable: func() (string, error) {
			if s.exePath == "" && s.exeErr == nil {
				return "/usr/local/bin/oktsec", nil
			}
			return s.exePath, s.exeErr
		},
	}
}

// TestConnectClaudeCode_InstallsGatewayAndHooks verifies the strict
// connect contract: `oktsec connect claude-code` registers the gateway
// AND installs the V2 hook manifest. Both must succeed for the helper
// to return success.
func TestConnectClaudeCode_InstallsGatewayAndHooks(t *testing.T) {
	stub := &stubLifecycleDeps{
		hasCLI:        true,
		installResult: claudecode.InstallResult{Wrote: true},
	}
	res, err := connectClaudeCodeRuntime(context.Background(),
		claudeCodeConnectOptions{Port: 9090, Endpoint: "/mcp", Mode: claudeConnectStrict},
		stub.deps())
	if err != nil {
		t.Fatalf("connectClaudeCodeRuntime: %v", err)
	}
	if stub.addCalls != 1 {
		t.Errorf("runMCPAdd calls = %d, want 1", stub.addCalls)
	}
	if stub.installCalls != 1 {
		t.Errorf("installHooksV2 calls = %d, want 1", stub.installCalls)
	}
	if !res.Connected() {
		t.Errorf("expected Connected() = true, got %+v", res)
	}
	if stub.installSeenOpt.GatewayPort != 9090 {
		t.Errorf("install opts GatewayPort = %d, want 9090", stub.installSeenOpt.GatewayPort)
	}
}

// TestConnectClaudeCode_HookFailureReturnsPartialError verifies strict
// mode: gateway succeeds but hooks fail, so the helper returns a
// non-nil error and the result records partial state.
func TestConnectClaudeCode_HookFailureReturnsPartialError(t *testing.T) {
	stub := &stubLifecycleDeps{
		hasCLI:     true,
		installErr: errors.New("simulated install failure"),
	}
	res, err := connectClaudeCodeRuntime(context.Background(),
		claudeCodeConnectOptions{Port: 9090, Endpoint: "/mcp", Mode: claudeConnectStrict},
		stub.deps())
	if err == nil {
		t.Fatal("expected non-nil error in strict mode when hook install fails")
	}
	if res.GatewayOK == false {
		t.Errorf("gateway should be OK; got %+v", res)
	}
	if res.HooksOK {
		t.Errorf("hooks must not be OK when install failed")
	}
}

// TestConnectClaudeCode_StrictMissingCLIErrors guards strict mode
// against silently degrading when the user explicitly asked to connect.
func TestConnectClaudeCode_StrictMissingCLIErrors(t *testing.T) {
	stub := &stubLifecycleDeps{hasCLI: false}
	_, err := connectClaudeCodeRuntime(context.Background(),
		claudeCodeConnectOptions{Mode: claudeConnectStrict},
		stub.deps())
	if err == nil {
		t.Fatal("expected error when claude CLI is missing in strict mode")
	}
}

// TestConnectClaudeCode_BestEffortMissingCLINoError ensures `oktsec run`
// keeps its best-effort posture when claude is not installed.
func TestConnectClaudeCode_BestEffortMissingCLINoError(t *testing.T) {
	stub := &stubLifecycleDeps{hasCLI: false}
	res, err := connectClaudeCodeRuntime(context.Background(),
		claudeCodeConnectOptions{Mode: claudeConnectBestEffort},
		stub.deps())
	if err != nil {
		t.Fatalf("best-effort mode must not return error when CLI is missing: %v", err)
	}
	if res.GatewayAttempted || res.HooksAttempted {
		t.Errorf("nothing should be attempted when CLI is missing")
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected a warning about the missing CLI")
	}
}

// TestDisconnectClaudeCode_RemovesGatewayAndHooks verifies the
// disconnect contract: gateway entry is removed AND every Oktsec-owned
// hook (V2 plus legacy V1) is uninstalled.
func TestDisconnectClaudeCode_RemovesGatewayAndHooks(t *testing.T) {
	stub := &stubLifecycleDeps{
		hasCLI:          true,
		uninstallResult: claudecode.UninstallResult{Wrote: true, RemovedV2: 12, RemovedV1: 2},
	}
	res, err := disconnectClaudeCodeRuntime(context.Background(),
		claudeCodeDisconnectOptions{},
		stub.deps())
	if err != nil {
		t.Fatalf("disconnectClaudeCodeRuntime: %v", err)
	}
	if stub.removeCalls != 1 {
		t.Errorf("runMCPRemove calls = %d, want 1", stub.removeCalls)
	}
	if stub.uninstallCalls != 1 {
		t.Errorf("uninstallHooksV2 calls = %d, want 1", stub.uninstallCalls)
	}
	if !stub.uninstallSeenOpt.IncludeLegacyV1 {
		t.Errorf("uninstall must request IncludeLegacyV1 = true")
	}
	if !res.GatewayOK || !res.HooksOK {
		t.Errorf("expected both sides OK; got %+v", res)
	}
}

// TestDisconnectClaudeCode_HookUninstallFailureReturnsPartialError
// verifies that when the gateway is removed but hook uninstall fails,
// the operator gets a non-zero exit and a partial-state message.
func TestDisconnectClaudeCode_HookUninstallFailureReturnsPartialError(t *testing.T) {
	stub := &stubLifecycleDeps{
		hasCLI:       true,
		uninstallErr: errors.New("simulated uninstall failure"),
	}
	_, err := disconnectClaudeCodeRuntime(context.Background(),
		claudeCodeDisconnectOptions{},
		stub.deps())
	if err == nil {
		t.Fatal("expected non-nil error when hook uninstall fails")
	}
	if !strings.Contains(err.Error(), "hook uninstall failed") {
		t.Errorf("error should mention partial disconnect; got %v", err)
	}
}

// TestDisconnectClaudeCode_GatewayMissingStillAttemptsHookUninstall
// verifies that when `claude mcp remove` reports the entry is already
// absent, hook uninstall still runs. Leaving Oktsec hooks behind after
// a "disconnect" creates a confusing state for the operator.
func TestDisconnectClaudeCode_GatewayMissingStillAttemptsHookUninstall(t *testing.T) {
	stub := &stubLifecycleDeps{
		hasCLI:    true,
		removeOut: []byte("Error: MCP server \"oktsec-gateway\" not found"),
		removeErr: errors.New("exit status 1"),
		uninstallResult: claudecode.UninstallResult{
			Wrote:     true,
			RemovedV2: 14,
		},
	}
	res, err := disconnectClaudeCodeRuntime(context.Background(),
		claudeCodeDisconnectOptions{},
		stub.deps())
	if err != nil {
		t.Fatalf("disconnect returned error when gateway was already absent: %v", err)
	}
	if stub.uninstallCalls != 1 {
		t.Errorf("uninstallHooksV2 must run even if gateway removal reports absent; got %d", stub.uninstallCalls)
	}
	if !res.GatewayOK {
		t.Errorf("already-absent should count as success")
	}
	if !res.HooksOK {
		t.Errorf("hooks should be OK; got %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected an informational warning about already-absent gateway")
	}
}

// TestPartialAndConnected_HelperContract pins the small predicate
// methods on the lifecycle result so callers can rely on them.
func TestPartialAndConnected_HelperContract(t *testing.T) {
	cases := []struct {
		name      string
		res       claudeCodeLifecycleResult
		partial   bool
		connected bool
	}{
		{
			name: "both ok",
			res: claudeCodeLifecycleResult{
				GatewayAttempted: true, GatewayOK: true,
				HooksAttempted: true, HooksOK: true,
			},
			partial: false, connected: true,
		},
		{
			name: "gateway only",
			res: claudeCodeLifecycleResult{
				GatewayAttempted: true, GatewayOK: true,
				HooksAttempted: true, HooksOK: false,
			},
			partial: true, connected: false,
		},
		{
			name: "hooks only",
			res: claudeCodeLifecycleResult{
				GatewayAttempted: true, GatewayOK: false,
				HooksAttempted: true, HooksOK: true,
			},
			partial: true, connected: false,
		},
		{
			name:      "nothing attempted",
			res:       claudeCodeLifecycleResult{},
			partial:   false,
			connected: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.Partial(); got != tc.partial {
				t.Errorf("Partial() = %t, want %t", got, tc.partial)
			}
			if got := tc.res.Connected(); got != tc.connected {
				t.Errorf("Connected() = %t, want %t", got, tc.connected)
			}
		})
	}
}
