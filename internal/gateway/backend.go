// Package gateway implements the MCP gateway mode — a Streamable HTTP MCP
// server that fronts one or more backend MCP servers, intercepting every
// tools/call with the oktsec security pipeline.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/config"
)

// MCPSession is the subset of mcp.ClientSession methods used by Backend.
// Extracted as an interface for testing.
type MCPSession interface {
	ListTools(ctx context.Context, params *mcp.ListToolsParams) (*mcp.ListToolsResult, error)
	CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error)
	Close() error
}

// Backend wraps a single backend MCP server connection.
type Backend struct {
	Name      string
	Config    config.MCPServerConfig
	Tools     []*mcp.Tool
	session   MCPSession
	proxyPort int // forward proxy port for egress sandbox (0 = not configured)
	logger    *slog.Logger
}

// NewBackend creates a backend that will connect to the given MCP server.
func NewBackend(name string, cfg config.MCPServerConfig, logger *slog.Logger) *Backend {
	return &Backend{
		Name:   name,
		Config: cfg,
		logger: logger,
	}
}

// SetProxyPort sets the forward proxy port used for egress sandboxing.
func (b *Backend) SetProxyPort(port int) {
	b.proxyPort = port
}

// NewBackendWithSession creates a backend with a pre-connected session (for testing).
func NewBackendWithSession(name string, s MCPSession, logger *slog.Logger) *Backend {
	return &Backend{
		Name:    name,
		session: s,
		logger:  logger,
	}
}

// Connect starts the transport, initializes the MCP protocol, and discovers tools.
func (b *Backend) Connect(ctx context.Context) error {
	if b.session == nil {
		s, err := b.createSession(ctx)
		if err != nil {
			return fmt.Errorf("backend %s: creating session: %w", b.Name, err)
		}
		b.session = s
	}

	// Discover tools (initialization is implicit in Client.Connect)
	result, err := b.session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("backend %s: list tools: %w", b.Name, err)
	}
	b.Tools = result.Tools
	b.logger.Info("backend connected", "name", b.Name, "tools", len(b.Tools))
	return nil
}

// CallTool forwards a tool call to the backend.
func (b *Backend) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	return b.session.CallTool(ctx, params)
}

// Close shuts down the backend connection.
func (b *Backend) Close() error {
	if b.session != nil {
		return b.session.Close()
	}
	return nil
}

// createSession builds the appropriate transport and connects to the backend.
func (b *Backend) createSession(ctx context.Context) (MCPSession, error) {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "oktsec-gateway",
		Version: "0.1.0",
	}, nil)

	var transport mcp.Transport
	switch b.Config.Transport {
	case "stdio":
		args := b.Config.Args
		cmd := exec.CommandContext(ctx, b.Config.Command, args...)
		cmd.Env = b.buildChildEnv(os.Environ())
		transport = &mcp.CommandTransport{Command: cmd}

	case "http":
		transport = &mcp.StreamableClientTransport{Endpoint: b.Config.URL}

	default:
		return nil, fmt.Errorf("unsupported transport: %s", b.Config.Transport)
	}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	return session, nil
}

// buildChildEnv assembles the env slice that a stdio backend's child
// process inherits. baseEnv is typically os.Environ(); tests pass a
// fixed slice for deterministic assertions.
//
// Layering:
//
//  1. baseEnv (host environment, copied so we never mutate it).
//  2. Egress-sandbox proxy env, when EgressSandbox is true. This
//     forces HTTP_PROXY / HTTPS_PROXY / ALL_PROXY (and lowercase
//     variants) to point at Oktsec's forward proxy and clears
//     NO_PROXY so nothing bypasses the sandbox.
//  3. Backend Env from the config. When the sandbox is active,
//     reserved proxy keys are dropped here with a warning so a
//     hostile or buggy backend config cannot redirect or disable
//     the sandbox. Non-proxy keys (NODE_OPTIONS, custom tokens,
//     etc.) still pass through.
func (b *Backend) buildChildEnv(baseEnv []string) []string {
	env := make([]string, len(baseEnv))
	copy(env, baseEnv)

	sandbox := b.Config.EgressSandbox
	if sandbox {
		port := b.proxyPort
		if port == 0 {
			port = 8083 // default forward proxy port
		}
		proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", port)
		env = setEnv(env, "HTTP_PROXY", proxyAddr)
		env = setEnv(env, "HTTPS_PROXY", proxyAddr)
		env = setEnv(env, "ALL_PROXY", proxyAddr)
		env = setEnv(env, "http_proxy", proxyAddr)
		env = setEnv(env, "https_proxy", proxyAddr)
		env = setEnv(env, "all_proxy", proxyAddr)
		env = setEnv(env, "NO_PROXY", "")
		env = setEnv(env, "no_proxy", "")
		b.logger.Info("egress sandbox active", "server", b.Name, "proxy", proxyAddr)
	}

	for k, v := range b.Config.Env {
		if sandbox && isReservedProxyEnvKey(k) {
			b.logger.Warn("egress sandbox ignored reserved proxy env from backend config",
				"server", b.Name, "key", k)
			continue
		}
		env = setEnv(env, k, v)
	}
	return env
}

// reservedProxyEnvKeys are the environment variable names through
// which a child process selects its outbound HTTP proxy. When the
// egress sandbox is active, Oktsec sets these to route traffic
// through the forward proxy; backend config must not override them.
//
// Net/http honours both upper and lower case forms, and many
// language runtimes (Python requests, Node fetch, curl) follow the
// same convention, so we treat each variant as a distinct reserved
// key.
var reservedProxyEnvKeys = map[string]struct{}{
	"HTTP_PROXY":  {},
	"HTTPS_PROXY": {},
	"ALL_PROXY":   {},
	"NO_PROXY":    {},
	"http_proxy":  {},
	"https_proxy": {},
	"all_proxy":   {},
	"no_proxy":    {},
}

// isReservedProxyEnvKey reports whether key controls outbound proxy
// behaviour in the child process.
func isReservedProxyEnvKey(key string) bool {
	_, ok := reservedProxyEnvKeys[key]
	return ok
}

// setEnv sets a key=value pair in an env slice, replacing an existing entry
// for the same key or appending a new one.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
