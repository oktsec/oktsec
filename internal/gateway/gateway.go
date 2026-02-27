package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/proxy"
)

type contextKey string

const agentContextKey contextKey = "oktsec-agent"

// toolMapping maps a frontend tool name to its backend.
type toolMapping struct {
	BackendName  string
	OriginalName string
	Backend      *Backend
}

// Gateway is the MCP security gateway server.
type Gateway struct {
	cfg         *config.Config
	mcpServer   *server.MCPServer
	httpServer  *http.Server
	ln          net.Listener
	backends    map[string]*Backend
	toolMap     map[string]toolMapping
	scanner     *engine.Scanner
	audit       *audit.Store
	webhooks    *proxy.WebhookNotifier
	rateLimiter *proxy.RateLimiter
	logger      *slog.Logger
}

// NewGateway creates a gateway from the given configuration.
// Callers must call Start to begin serving and Shutdown to stop.
func NewGateway(cfg *config.Config, logger *slog.Logger) (*Gateway, error) {
	scanner := engine.NewScanner(cfg.CustomRulesDir)

	auditStore, err := audit.NewStore(cfg.DBPath, logger, cfg.Quarantine.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("opening audit store: %w", err)
	}

	webhooks := proxy.NewWebhookNotifier(cfg.Webhooks, logger)
	rateLimiter := proxy.NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS)

	return &Gateway{
		cfg:         cfg,
		backends:    make(map[string]*Backend),
		toolMap:     make(map[string]toolMapping),
		scanner:     scanner,
		audit:       auditStore,
		webhooks:    webhooks,
		rateLimiter: rateLimiter,
		logger:      logger,
	}, nil
}

// newGatewayForTest creates a gateway with injected dependencies (no real scanner/audit).
func newGatewayForTest(cfg *config.Config, scanner *engine.Scanner, auditStore *audit.Store, logger *slog.Logger) *Gateway {
	return &Gateway{
		cfg:         cfg,
		backends:    make(map[string]*Backend),
		toolMap:     make(map[string]toolMapping),
		scanner:     scanner,
		audit:       auditStore,
		webhooks:    proxy.NewWebhookNotifier(nil, logger),
		rateLimiter: proxy.NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS),
		logger:      logger,
	}
}

// Start connects to all backends, discovers tools, and starts the HTTP server.
// It blocks until the server is shut down.
func (g *Gateway) Start(ctx context.Context) error {
	// Connect backends
	for name, cfg := range g.cfg.MCPServers {
		b := NewBackend(name, cfg, g.logger)
		if err := b.Connect(ctx); err != nil {
			return fmt.Errorf("connecting backend %s: %w", name, err)
		}
		g.backends[name] = b
	}

	if err := g.buildToolMap(); err != nil {
		return err
	}

	// Create MCP server and register tools
	g.mcpServer = server.NewMCPServer("oktsec-gateway", "0.1.0",
		server.WithToolCapabilities(true),
	)

	for frontendName, mapping := range g.toolMap {
		// Find the original tool definition
		var tool mcp.Tool
		for _, t := range mapping.Backend.Tools {
			if t.Name == mapping.OriginalName {
				tool = t
				break
			}
		}
		// Expose with the (possibly namespaced) frontend name
		tool.Name = frontendName
		g.mcpServer.AddTool(tool, g.makeHandler(mapping))
	}

	// Create Streamable HTTP server (used as http.Handler)
	streamable := server.NewStreamableHTTPServer(g.mcpServer,
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			agent := r.Header.Get("X-Oktsec-Agent")
			if agent == "" {
				agent = "unknown"
			}
			return context.WithValue(ctx, agentContextKey, agent)
		}),
	)

	// Bind with auto-port
	bind := g.cfg.Gateway.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}

	ln, actualPort, err := listenAutoPort(bind, g.cfg.Gateway.Port, g.logger)
	if err != nil {
		return fmt.Errorf("binding gateway port: %w", err)
	}
	g.ln = ln
	g.cfg.Gateway.Port = actualPort

	// Route the endpoint path to the streamable HTTP server
	mux := http.NewServeMux()
	mux.Handle(g.cfg.Gateway.EndpointPath, streamable)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": "0.1.0",
		})
	})

	g.httpServer = &http.Server{
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	g.logger.Info("gateway starting",
		"addr", g.ln.Addr().String(),
		"endpoint", g.cfg.Gateway.EndpointPath,
		"backends", len(g.backends),
		"tools", len(g.toolMap),
	)

	return g.httpServer.Serve(g.ln)
}

// Port returns the actual port the gateway is bound to.
func (g *Gateway) Port() int {
	return g.cfg.Gateway.Port
}

// Shutdown gracefully stops the gateway server and all backends.
func (g *Gateway) Shutdown(ctx context.Context) error {
	g.logger.Info("gateway shutting down")
	var firstErr error

	if g.httpServer != nil {
		if err := g.httpServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, b := range g.backends {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	g.scanner.Close()
	if err := g.audit.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// buildToolMap creates the frontend-to-backend tool mapping.
// Single backend: no prefix. Multiple backends with name conflicts get backendName_toolName.
func (g *Gateway) buildToolMap() error {
	if len(g.backends) == 0 {
		return fmt.Errorf("no backends connected")
	}

	// Count tool name occurrences to detect conflicts
	nameCounts := make(map[string]int)
	for _, b := range g.backends {
		for _, t := range b.Tools {
			nameCounts[t.Name]++
		}
	}

	for backendName, b := range g.backends {
		for _, t := range b.Tools {
			frontendName := t.Name
			if nameCounts[t.Name] > 1 {
				frontendName = backendName + "_" + t.Name
			}
			g.toolMap[frontendName] = toolMapping{
				BackendName:  backendName,
				OriginalName: t.Name,
				Backend:      b,
			}
		}
	}
	return nil
}

// makeHandler returns a ToolHandlerFunc that runs the security pipeline
// before forwarding the call to the backend.
func (g *Gateway) makeHandler(m toolMapping) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		msgID := uuid.New().String()

		// 1. Extract agent name from context
		agent, _ := ctx.Value(agentContextKey).(string)
		if agent == "" {
			agent = "unknown"
		}

		// 2. Rate limit check
		if !g.rateLimiter.Allow(agent) {
			g.logAudit(msgID, agent, m.OriginalName, "rejected", "rate_limited", "[]", start)
			return toolError("rate limit exceeded"), nil
		}

		// 3. Tool allowlist check
		if agentCfg, ok := g.cfg.Agents[agent]; ok {
			if agentCfg.Suspended {
				g.logAudit(msgID, agent, m.OriginalName, "rejected", "agent_suspended", "[]", start)
				return toolError("agent suspended"), nil
			}
			if len(agentCfg.AllowedTools) > 0 {
				allowed := false
				for _, t := range agentCfg.AllowedTools {
					if t == m.OriginalName {
						allowed = true
						break
					}
				}
				if !allowed {
					g.logAudit(msgID, agent, m.OriginalName, "blocked", "tool_not_allowed", "[]", start)
					return toolError(fmt.Sprintf("tool %q not allowed for agent %q", m.OriginalName, agent)), nil
				}
			}
		}

		// 4. Serialize arguments for scanning
		content := extractToolContent(m.OriginalName, req)

		// 5. Scan content
		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		outcome, err := g.scanner.ScanContent(scanCtx, content)
		if err != nil {
			g.logger.Error("scan failed", "error", err, "tool", m.OriginalName)
			g.logAudit(msgID, agent, m.OriginalName, "delivered", "scan_error", "[]", start)
			// Forward on scan error — fail open
		}

		if outcome == nil {
			outcome = &engine.ScanOutcome{Verdict: engine.VerdictClean}
		}

		// 6. Apply rule overrides
		applyRuleOverrides(g.cfg.Rules, outcome)

		// 7. Apply blocked content
		if agentCfg, ok := g.cfg.Agents[agent]; ok {
			applyBlockedContent(agentCfg, outcome)
		}

		// 8. Determine verdict
		findingsJSON := encodeFindings(outcome.Findings)
		status, decision := verdictToGateway(outcome.Verdict)

		// 9. Audit log
		g.logAudit(msgID, agent, m.OriginalName, status, decision, findingsJSON, start)

		// 10. Webhook notification if severe
		if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
			g.webhooks.Notify(proxy.WebhookEvent{
				Event:     "message_" + status,
				MessageID: msgID,
				From:      agent,
				To:        m.BackendName + "/" + m.OriginalName,
				Severity:  topSeverity(outcome.Findings),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}

		// 11. Block if verdict is block or quarantine
		if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
			return toolError(fmt.Sprintf("blocked by oktsec: %s (%d rules triggered)", decision, len(outcome.Findings))), nil
		}

		// 12. Forward to backend with original tool name
		req.Params.Name = m.OriginalName
		result, err := m.Backend.CallTool(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", m.BackendName, err)
		}

		// 13. Optionally scan response
		if g.cfg.Gateway.ScanResponses && result != nil {
			respContent := extractResultContent(result)
			if respContent != "" {
				respOutcome, err := g.scanner.ScanContent(scanCtx, respContent)
				if err == nil && respOutcome != nil {
					applyRuleOverrides(g.cfg.Rules, respOutcome)
					if respOutcome.Verdict == engine.VerdictBlock || respOutcome.Verdict == engine.VerdictQuarantine {
						g.logger.Warn("backend response blocked",
							"tool", m.OriginalName, "backend", m.BackendName, "verdict", respOutcome.Verdict)
						return toolError("backend response blocked by oktsec"), nil
					}
				}
			}
		}

		return result, nil
	}
}

// logAudit writes an audit entry for a gateway tool call.
func (g *Gateway) logAudit(msgID, agent, tool, status, decision, findingsJSON string, start time.Time) {
	g.audit.Log(audit.Entry{
		ID:             msgID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      agent,
		ToAgent:        "gateway/" + tool,
		ContentHash:    "",
		Status:         status,
		RulesTriggered: findingsJSON,
		PolicyDecision: decision,
		LatencyMs:      time.Since(start).Milliseconds(),
	})
}

// toolError creates a CallToolResult with IsError=true.
func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: msg},
		},
		IsError: true,
	}
}

// extractToolContent serializes tool name + arguments for scanning.
func extractToolContent(toolName string, req mcp.CallToolRequest) string {
	args := req.GetArguments()
	if len(args) == 0 {
		return toolName
	}
	data, err := json.Marshal(args)
	if err != nil {
		return toolName
	}
	return toolName + " " + string(data)
}

// extractResultContent extracts text from a CallToolResult for scanning.
func extractResultContent(result *mcp.CallToolResult) string {
	var parts []string
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	content := parts[0]
	for _, p := range parts[1:] {
		content += "\n" + p
	}
	return content
}

// applyBlockedContent escalates verdict to block if any finding's category
// matches the agent's blocked_content list.
func applyBlockedContent(agent config.Agent, outcome *engine.ScanOutcome) {
	if len(agent.BlockedContent) == 0 || len(outcome.Findings) == 0 {
		return
	}
	blocked := make(map[string]bool, len(agent.BlockedContent))
	for _, cat := range agent.BlockedContent {
		blocked[cat] = true
	}
	for _, f := range outcome.Findings {
		if blocked[f.Category] {
			outcome.Verdict = engine.VerdictBlock
			return
		}
	}
}

// verdictToGateway maps a verdict to (status, policyDecision).
func verdictToGateway(v engine.ScanVerdict) (status, decision string) {
	switch v {
	case engine.VerdictBlock:
		return "blocked", "content_blocked"
	case engine.VerdictQuarantine:
		return "quarantined", "content_quarantined"
	case engine.VerdictFlag:
		return "delivered", "content_flagged"
	default:
		return "delivered", "allow"
	}
}

// encodeFindings marshals findings to JSON or returns "[]".
func encodeFindings(findings []engine.FindingSummary) string {
	if len(findings) == 0 {
		return "[]"
	}
	data, err := json.Marshal(findings)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// topSeverity returns the first finding's severity, or "none".
func topSeverity(findings []engine.FindingSummary) string {
	if len(findings) > 0 {
		return findings[0].Severity
	}
	return "none"
}

// listenAutoPort tries the configured port; if busy, scans up to 10 higher ports.
func listenAutoPort(bind string, port int, logger *slog.Logger) (net.Listener, int, error) {
	addr := fmt.Sprintf("%s:%d", bind, port)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		actual := ln.Addr().(*net.TCPAddr).Port
		return ln, actual, nil
	}

	if !errors.Is(err, syscall.EADDRINUSE) && !isAddrInUse(err) {
		return nil, 0, err
	}

	logger.Warn("gateway port in use, searching for available port", "port", port)
	for offset := 1; offset <= 10; offset++ {
		tryPort := port + offset
		addr = fmt.Sprintf("%s:%d", bind, tryPort)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			logger.Info("using alternative gateway port", "original", port, "actual", tryPort)
			return ln, tryPort, nil
		}
	}
	return nil, 0, fmt.Errorf("port %d and next 10 ports are all in use", port)
}

func isAddrInUse(err error) bool {
	return err != nil && (errors.Is(err, syscall.EADDRINUSE) ||
		func() bool {
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				return errors.Is(opErr.Err, syscall.EADDRINUSE)
			}
			return false
		}())
}
