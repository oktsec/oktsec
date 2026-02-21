package mcp

import (
	"log/slog"

	"github.com/mark3labs/mcp-go/server"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// NewServer creates an MCP server exposing oktsec tools.
func NewServer(cfg *config.Config, scanner *engine.Scanner, auditStore *audit.Store, logger *slog.Logger) *server.MCPServer {
	s := server.NewMCPServer(
		"oktsec",
		"0.2.0",
		server.WithToolCapabilities(false),
		server.WithInstructions(
			"Oktsec is a security proxy for inter-agent communication. "+
				"Use these tools to scan messages for threats, verify agent identity, "+
				"query the audit log, and inspect security policies.",
		),
	)

	h := &handlers{
		cfg:     cfg,
		scanner: scanner,
		audit:   auditStore,
		logger:  logger,
	}

	s.AddTool(scanMessageTool(), h.handleScanMessage)
	s.AddTool(listAgentsTool(), h.handleListAgents)
	s.AddTool(auditQueryTool(), h.handleAuditQuery)
	s.AddTool(getPolicyTool(), h.handleGetPolicy)

	return s
}

// Serve runs the MCP server on stdio.
func Serve(s *server.MCPServer) error {
	return server.ServeStdio(s)
}
