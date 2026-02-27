package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMCPServer creates a simple MCP server with one tool for testing.
func newTestMCPServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "test-backend",
		Version: "1.0.0",
	}, nil)
	s.AddTool(
		&mcp.Tool{
			Name:        "greet",
			Description: "Say hello",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "Name to greet"},
				},
				"required": []string{"name"},
			},
		},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args map[string]any
			if len(req.Params.Arguments) > 0 {
				_ = json.Unmarshal(req.Params.Arguments, &args)
			}
			name, _ := args["name"].(string)
			if name == "" {
				name = "world"
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Hello, " + name + "!"}},
			}, nil
		},
	)
	return s
}

// connectInProcess creates an in-memory client session connected to the given server.
func connectInProcess(ctx context.Context, t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()

	// Server connects first
	_, err := srv.Connect(ctx, st, nil)
	require.NoError(t, err)

	// Client connects second
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	require.NoError(t, err)
	return cs
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBackend_ConnectAndListTools(t *testing.T) {
	ctx := context.Background()
	srv := newTestMCPServer()
	cs := connectInProcess(ctx, t, srv)

	b := NewBackendWithSession("test", cs, testLogger())
	err := b.Connect(ctx)
	require.NoError(t, err)

	assert.Len(t, b.Tools, 1)
	assert.Equal(t, "greet", b.Tools[0].Name)
}

func TestBackend_CallTool(t *testing.T) {
	ctx := context.Background()
	srv := newTestMCPServer()
	cs := connectInProcess(ctx, t, srv)

	b := NewBackendWithSession("test", cs, testLogger())
	err := b.Connect(ctx)
	require.NoError(t, err)

	result, err := b.CallTool(ctx, &mcp.CallToolParams{
		Name:      "greet",
		Arguments: map[string]any{"name": "oktsec"},
	})
	require.NoError(t, err)
	require.Len(t, result.Content, 1)

	tc, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected *mcp.TextContent")
	assert.Equal(t, "Hello, oktsec!", tc.Text)
}

func TestBackend_Close(t *testing.T) {
	ctx := context.Background()
	srv := newTestMCPServer()
	cs := connectInProcess(ctx, t, srv)

	b := NewBackendWithSession("test", cs, testLogger())
	err := b.Connect(ctx)
	require.NoError(t, err)

	err = b.Close()
	assert.NoError(t, err)
}
