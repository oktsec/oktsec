package commands

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors/claudecode"
)

// TestConnectClaudeCode_EnablesGatewayInSavedConfig pins the contract
// that `oktsec connect claude-code` is strict in the runtime sense: a
// successful return means the operator can run `oktsec run` / `oktsec
// serve` and the gateway will actually accept Claude Code's HTTP MCP
// transport. Before this fix, a legacy or default config with
// gateway.enabled: false left Claude Code pointing at 127.0.0.1:9090
// but the gateway never started.
func TestConnectClaudeCode_EnablesGatewayInSavedConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	keysDir := filepath.Join(dir, "keys")

	// Seed a config with gateway disabled, the same shape an operator
	// would have after editing oktsec.yaml by hand or carrying over
	// from a pre-Phase-4F install.
	seed := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Gateway: config.GatewayConfig{
			Enabled: false,
		},
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	// Stub the lifecycle deps so the test never invokes the real claude
	// CLI or mutates ~/.claude/settings.json.
	prevDeps := claudeCodeLifecycleDepsForCmd
	claudeCodeLifecycleDepsForCmd = func() claudeCodeLifecycleDeps {
		stub := &stubLifecycleDeps{
			hasCLI:        true,
			installResult: claudecode.InstallResult{Wrote: true},
		}
		return stub.deps()
	}
	t.Cleanup(func() { claudeCodeLifecycleDepsForCmd = prevDeps })

	prevCfg := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = prevCfg })

	cmd := newConnectCmd()
	cmd.SetArgs([]string{"claude-code"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("connect claude-code: %v", err)
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !saved.Gateway.Enabled {
		t.Errorf("connect claude-code must leave gateway.enabled = true; got %+v", saved.Gateway)
	}
	if saved.Gateway.Port != 9090 {
		t.Errorf("connect must default Gateway.Port to 9090 when blank; got %d", saved.Gateway.Port)
	}
	if saved.Gateway.EndpointPath != "/mcp" {
		t.Errorf("connect must default Gateway.EndpointPath to /mcp when blank; got %q", saved.Gateway.EndpointPath)
	}
	if _, exists := saved.Agents["claude-code"]; !exists {
		t.Errorf("connect must register the claude-code agent in saved config")
	}
}

// TestConnectClaudeCode_PersistsConfigBeforeMutatingClaude protects
// the ordering decision: strict connect saves oktsec.yaml first, then
// runs the lifecycle helper. If the lifecycle fails partway through,
// the operator at least has a config that matches the intent so
// `oktsec doctor claude-code` and a re-run can repair it.
func TestConnectClaudeCode_PersistsConfigBeforeMutatingClaude(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	keysDir := filepath.Join(dir, "keys")

	seed := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Gateway:  config.GatewayConfig{Enabled: false},
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	// Track whether config was already saved by the time the lifecycle
	// stub runs. We read it from disk inside the stub.
	gatewayEnabledAtMutationTime := false

	prevDeps := claudeCodeLifecycleDepsForCmd
	claudeCodeLifecycleDepsForCmd = func() claudeCodeLifecycleDeps {
		base := stubLifecycleDeps{hasCLI: true}
		d := base.deps()
		realAdd := d.runMCPAdd
		d.runMCPAdd = func(ctx context.Context, port int, endpoint string) ([]byte, error) {
			if loaded, err := config.Load(cfgPath); err == nil && loaded.Gateway.Enabled {
				gatewayEnabledAtMutationTime = true
			}
			return realAdd(ctx, port, endpoint)
		}
		return d
	}
	t.Cleanup(func() { claudeCodeLifecycleDepsForCmd = prevDeps })

	prevCfg := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = prevCfg })

	cmd := newConnectCmd()
	cmd.SetArgs([]string{"claude-code"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("connect claude-code: %v", err)
	}

	if !gatewayEnabledAtMutationTime {
		t.Errorf("config must be persisted with gateway enabled BEFORE Claude Code mutation runs")
	}
}

// TestConnectStdioClient_NoConfigSavedWhenWrapFails protects the
// non-Claude path from the pre-save ordering fix that ships with
// `connect claude-code`. Stdio clients must keep the previous order:
// wrap first, save oktsec.yaml only after wrapping succeeded.
// Otherwise a failed `connect cursor` (no client config to wrap)
// would leave a phantom cursor agent in oktsec.yaml. Use a temp HOME
// so the discover scanner cannot find a real cursor config from the
// developer machine running the test.
func TestConnectStdioClient_NoConfigSavedWhenWrapFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	keysDir := filepath.Join(dir, "keys")

	seed := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	prevCfg := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = prevCfg })

	cmd := newConnectCmd()
	cmd.SetArgs([]string{"cursor"})
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatal("connect cursor must fail when no cursor config exists")
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if _, exists := saved.Agents["cursor"]; exists {
		t.Errorf("cursor agent must not be persisted when wrap failed; got %+v", saved.Agents)
	}
}

// TestConnectClaudeCode_LegacyConfigKeepsCustomGatewayPort ensures we
// only fill blanks: an operator who set a custom port stays on it.
func TestConnectClaudeCode_LegacyConfigKeepsCustomGatewayPort(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	keysDir := filepath.Join(dir, "keys")

	seed := &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Gateway: config.GatewayConfig{
			Enabled:      false,
			Port:         9595,
			EndpointPath: "/oktsec-mcp",
		},
	}
	if err := seed.Save(cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	prevDeps := claudeCodeLifecycleDepsForCmd
	claudeCodeLifecycleDepsForCmd = func() claudeCodeLifecycleDeps {
		stub := &stubLifecycleDeps{
			hasCLI:        true,
			installResult: claudecode.InstallResult{Wrote: true},
		}
		return stub.deps()
	}
	t.Cleanup(func() { claudeCodeLifecycleDepsForCmd = prevDeps })

	prevCfg := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = prevCfg })

	cmd := newConnectCmd()
	cmd.SetArgs([]string{"claude-code"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !saved.Gateway.Enabled {
		t.Errorf("gateway must end up enabled")
	}
	if saved.Gateway.Port != 9595 {
		t.Errorf("custom port must be preserved; got %d, want 9595", saved.Gateway.Port)
	}
	if saved.Gateway.EndpointPath != "/oktsec-mcp" {
		t.Errorf("custom endpoint must be preserved; got %q", saved.Gateway.EndpointPath)
	}
}
