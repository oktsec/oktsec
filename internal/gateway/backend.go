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

		// Egress sandbox: inject proxy env vars so all HTTP traffic from the
		// child process routes through oktsec's forward proxy where egress
		// policies (domain allow/block, content scanning) are enforced.
		if b.Config.EgressSandbox {
			port := b.proxyPort
			if port == 0 {
				port = 8083 // default forward proxy port
			}
			proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", port)
			// Start with host env so child has PATH, HOME, etc.
			cmd.Env = os.Environ()
			cmd.Env = setEnv(cmd.Env, "HTTP_PROXY", proxyAddr)
			cmd.Env = setEnv(cmd.Env, "HTTPS_PROXY", proxyAddr)
			cmd.Env = setEnv(cmd.Env, "http_proxy", proxyAddr)
			cmd.Env = setEnv(cmd.Env, "https_proxy", proxyAddr)
			cmd.Env = setEnv(cmd.Env, "NO_PROXY", "")
			cmd.Env = setEnv(cmd.Env, "no_proxy", "")
			b.logger.Info("egress sandbox active", "server", b.Name, "proxy", proxyAddr)
		}

		// Apply user's custom env vars (overrides sandbox vars if set)
		for k, v := range b.Config.Env {
			if cmd.Env == nil {
				cmd.Env = os.Environ()
			}
			cmd.Env = setEnv(cmd.Env, k, v)
		}
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
