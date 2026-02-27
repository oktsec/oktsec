// Package gateway implements the MCP gateway mode — a Streamable HTTP MCP
// server that fronts one or more backend MCP servers, intercepting every
// tools/call with the oktsec security pipeline.
package gateway

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/oktsec/oktsec/internal/config"
)

// MCPClient is the subset of mcp-go client methods used by Backend.
// Extracted as an interface for testing.
type MCPClient interface {
	Initialize(ctx context.Context, request mcp.InitializeRequest) (*mcp.InitializeResult, error)
	ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error)
	CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
	Close() error
}

// Backend wraps a single backend MCP server connection.
type Backend struct {
	Name   string
	Config config.MCPServerConfig
	Tools  []mcp.Tool
	client MCPClient
	logger *slog.Logger
}

// NewBackend creates a backend that will connect to the given MCP server.
func NewBackend(name string, cfg config.MCPServerConfig, logger *slog.Logger) *Backend {
	return &Backend{
		Name:   name,
		Config: cfg,
		logger: logger,
	}
}

// NewBackendWithClient creates a backend with a pre-initialized client (for testing).
func NewBackendWithClient(name string, c MCPClient, logger *slog.Logger) *Backend {
	return &Backend{
		Name:   name,
		client: c,
		logger: logger,
	}
}

// Connect starts the transport, initializes the MCP protocol, and discovers tools.
func (b *Backend) Connect(ctx context.Context) error {
	if b.client == nil {
		c, err := b.createClient()
		if err != nil {
			return fmt.Errorf("backend %s: creating client: %w", b.Name, err)
		}
		b.client = c
	}

	// Initialize MCP protocol
	_, err := b.client.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "oktsec-gateway",
				Version: "0.1.0",
			},
		},
	})
	if err != nil {
		return fmt.Errorf("backend %s: initialize: %w", b.Name, err)
	}

	// Discover tools
	result, err := b.client.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return fmt.Errorf("backend %s: list tools: %w", b.Name, err)
	}
	b.Tools = result.Tools
	b.logger.Info("backend connected", "name", b.Name, "tools", len(b.Tools))
	return nil
}

// CallTool forwards a tool call to the backend.
func (b *Backend) CallTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return b.client.CallTool(ctx, req)
}

// Close shuts down the backend connection.
func (b *Backend) Close() error {
	if b.client != nil {
		return b.client.Close()
	}
	return nil
}

// createClient builds the appropriate mcp-go client based on transport type.
func (b *Backend) createClient() (MCPClient, error) {
	switch b.Config.Transport {
	case "stdio":
		var env []string
		for k, v := range b.Config.Env {
			env = append(env, k+"="+v)
		}
		c, err := client.NewStdioMCPClient(b.Config.Command, env, b.Config.Args...)
		if err != nil {
			return nil, fmt.Errorf("stdio transport: %w", err)
		}
		return c, nil

	case "http":
		c, err := client.NewStreamableHttpClient(b.Config.URL)
		if err != nil {
			return nil, fmt.Errorf("http transport: %w", err)
		}
		return c, nil

	default:
		return nil, fmt.Errorf("unsupported transport: %s", b.Config.Transport)
	}
}
