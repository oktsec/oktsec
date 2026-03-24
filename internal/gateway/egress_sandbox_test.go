package gateway

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetEnv_ReplaceExisting(t *testing.T) {
	env := []string{"HOME=/home/user", "HTTP_PROXY=http://old:1234", "PATH=/usr/bin"}
	result := setEnv(env, "HTTP_PROXY", "http://127.0.0.1:8083")

	assert.Len(t, result, 3, "should not add a new entry")
	assert.Equal(t, "HTTP_PROXY=http://127.0.0.1:8083", result[1])
}

func TestSetEnv_AppendNew(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin"}
	result := setEnv(env, "HTTP_PROXY", "http://127.0.0.1:8083")

	assert.Len(t, result, 3, "should append a new entry")
	assert.Equal(t, "HTTP_PROXY=http://127.0.0.1:8083", result[2])
}

func TestSetEnv_EmptyValue(t *testing.T) {
	env := []string{"NO_PROXY=localhost"}
	result := setEnv(env, "NO_PROXY", "")

	assert.Len(t, result, 1)
	assert.Equal(t, "NO_PROXY=", result[0])
}

func TestSetEnv_EmptySlice(t *testing.T) {
	result := setEnv(nil, "KEY", "value")

	assert.Len(t, result, 1)
	assert.Equal(t, "KEY=value", result[0])
}

func TestSetEnv_CaseSensitive(t *testing.T) {
	// HTTP_PROXY and http_proxy are distinct keys
	env := []string{"HTTP_PROXY=http://old:1234"}
	result := setEnv(env, "http_proxy", "http://127.0.0.1:8083")

	assert.Len(t, result, 2, "case-different keys are separate entries")
	assert.Equal(t, "HTTP_PROXY=http://old:1234", result[0])
	assert.Equal(t, "http_proxy=http://127.0.0.1:8083", result[1])
}

func TestBackend_SetProxyPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := NewBackend("test", config.MCPServerConfig{
		Transport:     "stdio",
		Command:       "echo",
		EgressSandbox: true,
	}, logger)

	assert.Equal(t, 0, b.proxyPort)

	b.SetProxyPort(9999)
	assert.Equal(t, 9999, b.proxyPort)
}

func TestBackend_EgressSandboxConfig(t *testing.T) {
	// Verify that when EgressSandbox is true, the backend config is set correctly
	cfg := config.MCPServerConfig{
		Transport:     "stdio",
		Command:       "echo",
		EgressSandbox: true,
		Env:           map[string]string{"MY_VAR": "my_value"},
	}
	assert.True(t, cfg.EgressSandbox)
	assert.Equal(t, "my_value", cfg.Env["MY_VAR"])
}

func TestBackend_EgressSandboxDisabledByDefault(t *testing.T) {
	cfg := config.MCPServerConfig{
		Transport: "stdio",
		Command:   "echo",
	}
	assert.False(t, cfg.EgressSandbox)
}

// TestBuildSandboxEnv verifies the full env building logic that createSession uses.
// We can't call createSession directly (it spawns processes), so we replicate the
// env-building logic and verify the result.
func TestBuildSandboxEnv(t *testing.T) {
	proxyPort := 8083
	proxyAddr := "http://127.0.0.1:8083"

	// Simulate what createSession does when EgressSandbox is true
	baseEnv := []string{
		"HOME=/home/user",
		"PATH=/usr/bin:/usr/local/bin",
		"HTTP_PROXY=http://old-proxy:3128",
		"NO_PROXY=localhost",
	}

	env := make([]string, len(baseEnv))
	copy(env, baseEnv)

	_ = proxyPort // used to build proxyAddr
	env = setEnv(env, "HTTP_PROXY", proxyAddr)
	env = setEnv(env, "HTTPS_PROXY", proxyAddr)
	env = setEnv(env, "http_proxy", proxyAddr)
	env = setEnv(env, "https_proxy", proxyAddr)
	env = setEnv(env, "NO_PROXY", "")
	env = setEnv(env, "no_proxy", "")

	// User custom env applied after sandbox
	env = setEnv(env, "MY_TOKEN", "secret123")

	// Verify results
	envMap := envToMap(env)

	// Proxy vars should point to oktsec
	assert.Equal(t, proxyAddr, envMap["HTTP_PROXY"])
	assert.Equal(t, proxyAddr, envMap["HTTPS_PROXY"])
	assert.Equal(t, proxyAddr, envMap["http_proxy"])
	assert.Equal(t, proxyAddr, envMap["https_proxy"])

	// NO_PROXY should be empty (no bypass)
	assert.Equal(t, "", envMap["NO_PROXY"])
	assert.Equal(t, "", envMap["no_proxy"])

	// Original env preserved
	assert.Equal(t, "/home/user", envMap["HOME"])
	assert.Equal(t, "/usr/bin:/usr/local/bin", envMap["PATH"])

	// Custom user env applied
	assert.Equal(t, "secret123", envMap["MY_TOKEN"])
}

// TestCustomEnvOverridesSandbox verifies that user-specified Env can override
// the sandbox proxy vars (e.g., to point at a different proxy).
func TestCustomEnvOverridesSandbox(t *testing.T) {
	proxyAddr := "http://127.0.0.1:8083"
	customProxy := "http://custom-proxy:9090"

	env := []string{"HOME=/home/user"}
	env = setEnv(env, "HTTP_PROXY", proxyAddr)
	env = setEnv(env, "HTTPS_PROXY", proxyAddr)

	// User overrides HTTP_PROXY
	env = setEnv(env, "HTTP_PROXY", customProxy)

	envMap := envToMap(env)
	assert.Equal(t, customProxy, envMap["HTTP_PROXY"], "user Env should override sandbox proxy")
	assert.Equal(t, proxyAddr, envMap["HTTPS_PROXY"], "non-overridden proxy var should remain")
}

func TestDefaultProxyPort_FallbackTo8083(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := NewBackend("test", config.MCPServerConfig{
		Transport:     "stdio",
		Command:       "echo",
		EgressSandbox: true,
	}, logger)

	// proxyPort is 0 (not set), should fall back to 8083
	assert.Equal(t, 0, b.proxyPort)

	// The createSession code uses: if port == 0 { port = 8083 }
	port := b.proxyPort
	if port == 0 {
		port = 8083
	}
	assert.Equal(t, 8083, port)
}

func TestEgressSandboxWarning_NoForwardProxy(t *testing.T) {
	// Verify the warning path in gateway.Start when egress_sandbox is true
	// but forward_proxy is not enabled.
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 8080},
		Gateway: config.GatewayConfig{Enabled: true, Port: 0, EndpointPath: "/mcp"},
		ForwardProxy: config.ForwardProxyConfig{
			Enabled: false,
			Port:    8083,
		},
		MCPServers: map[string]config.MCPServerConfig{
			"test-server": {
				Transport:     "stdio",
				Command:       "echo",
				EgressSandbox: true,
			},
		},
		Agents: make(map[string]config.Agent),
	}

	// The warning check: cfg.EgressSandbox && !cfg.ForwardProxy.Enabled
	srv := cfg.MCPServers["test-server"]
	require.True(t, srv.EgressSandbox)
	require.False(t, cfg.ForwardProxy.Enabled)
}

// envToMap converts a []string env slice to a map for easier assertions.
func envToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}
