package gateway

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMCPServer creates a simple MCP server with one tool for testing.
func newTestMCPServer() *server.MCPServer {
	s := server.NewMCPServer("test-backend", "1.0.0",
		server.WithToolCapabilities(true),
	)
	s.AddTool(
		mcp.NewTool("greet",
			mcp.WithDescription("Say hello"),
			mcp.WithString("name", mcp.Description("Name to greet"), mcp.Required()),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := req.GetString("name", "world")
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{Type: "text", Text: "Hello, " + name + "!"},
				},
			}, nil
		},
	)
	return s
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBackend_ConnectAndListTools(t *testing.T) {
	srv := newTestMCPServer()
	c, err := client.NewInProcessClient(srv)
	require.NoError(t, err)

	b := NewBackendWithClient("test", c, testLogger())
	err = b.Connect(context.Background())
	require.NoError(t, err)

	assert.Len(t, b.Tools, 1)
	assert.Equal(t, "greet", b.Tools[0].Name)
}

func TestBackend_CallTool(t *testing.T) {
	srv := newTestMCPServer()
	c, err := client.NewInProcessClient(srv)
	require.NoError(t, err)

	b := NewBackendWithClient("test", c, testLogger())
	err = b.Connect(context.Background())
	require.NoError(t, err)

	result, err := b.CallTool(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "greet",
			Arguments: map[string]any{"name": "oktsec"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.Content, 1)

	tc, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected TextContent")
	assert.Equal(t, "Hello, oktsec!", tc.Text)
}

func TestBackend_Close(t *testing.T) {
	srv := newTestMCPServer()
	c, err := client.NewInProcessClient(srv)
	require.NoError(t, err)

	b := NewBackendWithClient("test", c, testLogger())
	err = b.Connect(context.Background())
	require.NoError(t, err)

	err = b.Close()
	assert.NoError(t, err)
}
