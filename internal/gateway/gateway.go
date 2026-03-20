package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/llm"
	"github.com/oktsec/oktsec/internal/mcputil"
	"github.com/oktsec/oktsec/internal/netutil"
	"github.com/oktsec/oktsec/internal/proxy"
	"github.com/oktsec/oktsec/internal/verdict"
)

// Version is set from the CLI at startup (via ldflags).
var Version = "dev"

type contextKey string

const agentContextKey contextKey = "oktsec-agent"
const sessionContextKey contextKey = "oktsec-session"
const delegationContextKey contextKey = "oktsec-delegation"

// toolMapping maps a frontend tool name to its backend.
type toolMapping struct {
	BackendName  string
	OriginalName string
	Backend      *Backend
}

// Gateway is the MCP security gateway server.
type Gateway struct {
	cfg               *config.Config
	mcpServer         *mcp.Server
	httpServer        *http.Server
	ln                net.Listener
	backends          map[string]*Backend
	toolMap           map[string]toolMapping
	scanner           *engine.Scanner
	audit             *audit.Store
	webhooks          *proxy.WebhookNotifier
	rateLimiter       *proxy.RateLimiter
	policyEnforcer    *ToolPolicyEnforcer
	constraintChecker *ConstraintChecker
	llmQueue          *llm.Queue
	signalDetector    *llm.SignalDetector
	escalationTracker *llm.EscalationTracker
	hooksHandler      http.Handler
	logger            *slog.Logger
	registeredAgents  map[string]bool
	registeredMu      sync.Mutex
	cfgPath           string
}

// NewGateway creates a gateway from the given configuration.
// Callers must call Start to begin serving and Shutdown to stop.
// If sharedStore is non-nil, the gateway uses it instead of creating its own.
// This avoids dual-store issues when proxy and gateway run in the same process.
func NewGateway(cfg *config.Config, logger *slog.Logger, sharedStore *audit.Store) (*Gateway, error) {
	scanner := engine.NewScanner(cfg.CustomRulesDir)

	auditStore := sharedStore
	if auditStore == nil {
		dbDSN := cfg.DBPath
		if cfg.DBBackend == "postgres" || cfg.DBBackend == "postgresql" {
			dbDSN = cfg.DBDSN
		}
		var err error
		auditStore, err = audit.Open(cfg.DBBackend, dbDSN, logger, cfg.Quarantine.RetentionDays)
		if err != nil {
			return nil, fmt.Errorf("opening audit store: %w", err)
		}
	}

	webhooks := proxy.NewWebhookNotifier(cfg.Webhooks, logger)
	rateLimiter := proxy.NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS)

	agentConstraints, agentChainRules := buildConstraintMaps(cfg)

	return &Gateway{
		cfg:               cfg,
		backends:          make(map[string]*Backend),
		toolMap:           make(map[string]toolMapping),
		scanner:           scanner,
		audit:             auditStore,
		webhooks:          webhooks,
		rateLimiter:       rateLimiter,
		policyEnforcer:    NewToolPolicyEnforcer(),
		constraintChecker: NewConstraintChecker(agentConstraints, agentChainRules),
		logger:           logger,
		registeredAgents: make(map[string]bool),
	}, nil
}

// newGatewayForTest creates a gateway with injected dependencies (no real scanner/audit).
func newGatewayForTest(cfg *config.Config, scanner *engine.Scanner, auditStore *audit.Store, logger *slog.Logger) *Gateway {
	agentConstraints, agentChainRules := buildConstraintMaps(cfg)
	return &Gateway{
		cfg:               cfg,
		backends:          make(map[string]*Backend),
		toolMap:           make(map[string]toolMapping),
		scanner:           scanner,
		audit:             auditStore,
		webhooks:          proxy.NewWebhookNotifier(nil, logger),
		rateLimiter:       proxy.NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS),
		policyEnforcer:    NewToolPolicyEnforcer(),
		constraintChecker: NewConstraintChecker(agentConstraints, agentChainRules),
		logger:            logger,
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

	if len(g.backends) > 0 {
		if err := g.buildToolMap(); err != nil {
			return err
		}
		g.filterPoisonedTools()
	}

	// Create MCP server and register tools
	g.mcpServer = mcp.NewServer(&mcp.Implementation{
		Name:    "oktsec-gateway",
		Version: Version,
	}, nil)

	for frontendName, mapping := range g.toolMap {
		// Find the original tool definition
		var tool *mcp.Tool
		for _, t := range mapping.Backend.Tools {
			if t.Name == mapping.OriginalName {
				tool = t
				break
			}
		}
		if tool == nil {
			continue
		}
		// Clone and expose with the (possibly namespaced) frontend name
		toolCopy := *tool
		toolCopy.Name = frontendName
		toolCopy.InputSchema = buildSchemaWithAgent(tool.InputSchema)
		g.mcpServer.AddTool(&toolCopy, g.makeHandler(mapping))
	}

	// Create Streamable HTTP handler with middleware for agent header extraction
	streamable := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return g.mcpServer },
		nil,
	)

	// Wrap with middleware for agent header and session ID injection
	agentMiddleware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := r.Header.Get("X-Oktsec-Agent")
		if agent == "" {
			agent = "unknown"
		}
		ctx := context.WithValue(r.Context(), agentContextKey, agent)
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			ctx = context.WithValue(ctx, sessionContextKey, sid)
		}
		if del := r.Header.Get("X-Oktsec-Delegation"); del != "" {
			ctx = context.WithValue(ctx, delegationContextKey, del)
		}
		streamable.ServeHTTP(w, r.WithContext(ctx))
	})

	// Bind with auto-port
	bind := g.cfg.Gateway.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}

	ln, actualPort, err := netutil.ListenAutoPort(bind, g.cfg.Gateway.Port, g.logger)
	if err != nil {
		return fmt.Errorf("binding gateway port: %w", err)
	}
	g.ln = ln
	g.cfg.Gateway.Port = actualPort

	// Route the endpoint path to the streamable HTTP handler
	mux := http.NewServeMux()
	mux.Handle(g.cfg.Gateway.EndpointPath, agentMiddleware)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": Version,
		})
	})

	// Hook endpoint: receives tool-call telemetry from any MCP client.
	if g.hooksHandler != nil {
		mux.Handle("POST /hooks/event", g.hooksHandler)
	}

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

// filterPoisonedTools scans every tool description through the security engine
// and removes tools whose descriptions trigger a block or quarantine verdict.
func (g *Gateway) filterPoisonedTools() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for frontendName, mapping := range g.toolMap {
		var tool *mcp.Tool
		for _, t := range mapping.Backend.Tools {
			if t.Name == mapping.OriginalName {
				tool = t
				break
			}
		}
		if tool == nil || tool.Description == "" {
			continue
		}

		outcome, err := g.scanner.ScanContent(ctx, tool.Description)
		if err != nil {
			g.logger.Warn("failed to scan tool description, keeping tool",
				"tool", frontendName, "error", err)
			continue
		}
		if outcome != nil && (outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine) {
			g.logger.Warn("removing poisoned tool",
				"tool", frontendName,
				"backend", mapping.BackendName,
				"verdict", outcome.Verdict,
				"findings", len(outcome.Findings),
			)
			delete(g.toolMap, frontendName)
		}
	}
}

// makeHandler returns a ToolHandler that runs the security pipeline
// before forwarding the call to the backend.
func (g *Gateway) makeHandler(m toolMapping) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		msgID := uuid.New().String()

		// 1. Extract agent name from context (parent identity from HTTP header)
		agent, _ := ctx.Value(agentContextKey).(string)
		if agent == "" {
			agent = "unknown"
		}

		// 1a. Extract sub-agent identity from tool arguments.
		// The HTTP header (agent) is the authoritative identity for all
		// security decisions (ACL, policy, suspension checks). The
		// _oktsec_agent parameter is logged as metadata but cannot
		// override policy — this prevents agent spoofing.
		headerAgent := agent
		subAgent := extractAndStripAgentParam(req)
		if subAgent != "" {
			// Validate: only trust sub-agent if the header agent is
			// configured and not suspended.
			if agentCfg, ok := g.cfg.Agents[headerAgent]; ok && !agentCfg.Suspended {
				agent = subAgent
				g.autoRegisterAgent(agent)
			} else {
				g.logger.Warn("ignoring _oktsec_agent: header agent not configured or suspended",
					"header_agent", headerAgent,
					"claimed_agent", subAgent,
				)
				// Keep using headerAgent for all checks
			}
		}

		// 1b. Extract tool arguments summary for audit (after stripping _oktsec_agent)
		toolArgs := summarizeToolArgs(req)

		// 1c. Extract MCP session ID for sub-agent tracking
		var sessionID string
		if req.Session != nil {
			sessionID = req.Session.ID()
		}

		// 1d. Verify delegation chain if present
		var delegationChainHash, delegationChainSummary string
		if delHeader, _ := ctx.Value(delegationContextKey).(string); delHeader != "" {
			chainResult := g.verifyDelegationHeader(delHeader)
			if chainResult.Valid {
				delegationChainHash = chainResult.ChainHash
				delegationChainSummary = chainResult.Root + " -> " + chainResult.Delegate
				if chainResult.Depth > 2 {
					delegationChainSummary = fmt.Sprintf("%s -> ... -> %s (%d hops)", chainResult.Root, chainResult.Delegate, chainResult.Depth)
				}
				g.logger.Debug("delegation chain verified",
					"root", chainResult.Root, "delegate", chainResult.Delegate,
					"depth", chainResult.Depth)
			} else {
				g.logger.Warn("delegation chain invalid",
					"agent", agent, "reason", chainResult.Reason)
			}
		}

		// 2. Rate limit check
		if !g.rateLimiter.Allow(agent) {
			g.logAudit(msgID, agent, m.OriginalName, audit.StatusRejected, audit.DecisionRateLimited, "[]", toolArgs, sessionID, start)
			return toolError("rate limit exceeded"), nil
		}

		// 3. Tool allowlist check
		if agentCfg, ok := g.cfg.Agents[agent]; ok {
			if agentCfg.Suspended {
				g.logAudit(msgID, agent, m.OriginalName, audit.StatusRejected, audit.DecisionAgentSuspended, "[]", toolArgs, sessionID, start)
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
					g.logAudit(msgID, agent, m.OriginalName, audit.StatusBlocked, audit.DecisionToolNotAllowed, "[]", toolArgs, sessionID, start)
					return toolError(fmt.Sprintf("tool %q not allowed for agent %q", m.OriginalName, agent)), nil
				}
			}
		}

		// 3b. Tool policy enforcement (spending limits, rate limits, approval thresholds)
		if agentCfg, ok := g.cfg.Agents[agent]; ok && agentCfg.ToolPolicies != nil {
			if policy, hasPolicy := agentCfg.ToolPolicies[m.OriginalName]; hasPolicy {
				amount := ExtractAmount(mcputil.GetArguments(req.Params.Arguments))
				result := g.policyEnforcer.Check(agent, m.OriginalName, amount, policy)
				if !result.Allowed {
					status := audit.StatusBlocked
					if result.Decision == "quarantine_approval" {
						status = audit.StatusQuarantined
					}
					g.logAudit(msgID, agent, m.OriginalName, status, result.Decision, "[]", toolArgs, sessionID, start)
					return toolError(fmt.Sprintf("tool policy: %s", result.Reason)), nil
				}
			}
		}

		// 3c. Tool constraint validation (parameter patterns, chain rules)
		if g.constraintChecker != nil {
			params := make(map[string]string)
			for k, v := range mcputil.GetArguments(req.Params.Arguments) {
				if s, ok := v.(string); ok {
					params[k] = s
				}
			}
			result := g.constraintChecker.CheckToolCall(agent, m.OriginalName, params)
			if !result.Allowed {
				g.logAudit(msgID, agent, m.OriginalName, audit.StatusBlocked, audit.DecisionConstraintViolated, "[]", toolArgs, sessionID, start)
				return toolError(fmt.Sprintf("constraint: %s", result.Reason)), nil
			}
		}

		// 4. Serialize arguments for scanning
		content := extractToolContent(m.OriginalName, req)

		// 5. Scan content (with tool context for built-in exemptions)
		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		outcome, err := g.scanner.ScanContentWithTool(scanCtx, content, m.OriginalName)
		if err != nil {
			g.logger.Error("scan failed", "error", err, "tool", m.OriginalName)
			g.logAudit(msgID, agent, m.OriginalName, audit.StatusDelivered, audit.DecisionScanError, "[]", toolArgs, sessionID, start)
			// Forward on scan error — fail open
		}

		if outcome == nil {
			outcome = &engine.ScanOutcome{Verdict: engine.VerdictClean}
		}

		// 6. Apply tool-scoped rule overrides (PostAguara: built-in
		// exemptions already applied by Aguara via WithToolName).
		verdict.ApplyToolScopedOverridesPostAguara(g.cfg.Rules, outcome, m.OriginalName)

		// 6b. Apply agent scan profile if explicitly configured.
		if agentCfg, ok := g.cfg.Agents[agent]; ok && agentCfg.ScanProfile != "" {
			verdict.ApplyScanProfile(agentCfg.ScanProfile, outcome, m.OriginalName)
		}

		// If all findings were removed by tool scoping, reset to clean.
		if len(outcome.Findings) == 0 {
			outcome.Verdict = engine.VerdictClean
		}

		// 7. Apply blocked content
		if agentCfg, ok := g.cfg.Agents[agent]; ok {
			verdict.ApplyBlockedContent(agentCfg, outcome)
		}

		// 7b. LLM-driven agent escalation (async feedback loop)
		if g.escalationTracker != nil && g.escalationTracker.IsEscalated(agent) {
			outcome.Verdict = verdict.EscalateOneLevel(outcome.Verdict)
		}

		// 8. Determine verdict
		findingsJSON := verdict.EncodeFindings(outcome.Findings)
		status, decision := verdictToGateway(outcome.Verdict)

		// 9. Audit log (with delegation chain if verified)
		g.logAudit(msgID, agent, m.OriginalName, status, decision, findingsJSON, toolArgs, sessionID, start, delegationChainHash, delegationChainSummary)

		// 9a. Enqueue quarantined items for human review
		if outcome.Verdict == engine.VerdictQuarantine {
			expiryHours := g.cfg.Quarantine.ExpiryHours
			if expiryHours <= 0 {
				expiryHours = 24
			}
			_ = g.audit.Enqueue(audit.QuarantineItem{
				ID:             msgID,
				AuditEntryID:   msgID,
				Content:        content,
				FromAgent:      agent,
				ToAgent:        m.OriginalName,
				Status:         audit.QStatusPending,
				ExpiresAt:      time.Now().Add(time.Duration(expiryHours) * time.Hour).UTC().Format(time.RFC3339),
				CreatedAt:      time.Now().UTC().Format(time.RFC3339),
				RulesTriggered: findingsJSON,
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
			})
		}

		// 9b. Record tool call for constraint chain rule tracking
		if g.constraintChecker != nil {
			g.constraintChecker.RecordToolCall(agent, m.OriginalName)
		}

		// 9b. Async LLM analysis (non-blocking)
		g.submitToLLM(agent, m.OriginalName, content, outcome.Verdict, outcome.Findings)

		// 10. Webhook notification if severe
		if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
			g.webhooks.Notify(proxy.WebhookEvent{
				Event:     "message_" + status,
				MessageID: msgID,
				From:      agent,
				To:        m.BackendName + "/" + m.OriginalName,
				Severity:  verdict.TopSeverity(outcome.Findings),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}

		// 11. Block if verdict is block or quarantine
		if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
			return toolError(fmt.Sprintf("blocked by oktsec: %s (%d rules triggered)", decision, len(outcome.Findings))), nil
		}

		// 12. Forward to backend with original tool name
		callParams := &mcp.CallToolParams{
			Name:      m.OriginalName,
			Arguments: mcputil.GetArguments(req.Params.Arguments),
		}
		result, err := m.Backend.CallTool(ctx, callParams)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", m.BackendName, err)
		}

		// 12b. Record successful call for tool policy tracking
		if agentCfg, ok := g.cfg.Agents[agent]; ok && agentCfg.ToolPolicies != nil {
			if _, hasPolicy := agentCfg.ToolPolicies[m.OriginalName]; hasPolicy {
				amount := ExtractAmount(mcputil.GetArguments(req.Params.Arguments))
				g.policyEnforcer.Record(agent, m.OriginalName, amount)
			}
		}

		// 13. Optionally scan response
		if g.cfg.Gateway.ScanResponses && result != nil {
			respContent := extractResultContent(result)
			if respContent != "" {
				respOutcome, err := g.scanner.ScanContentWithTool(scanCtx, respContent, m.OriginalName)
				if err == nil && respOutcome != nil {
					verdict.ApplyToolScopedOverridesPostAguara(g.cfg.Rules, respOutcome, m.OriginalName)
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

// SetCfgPath sets the config file path for auto-registration persistence.
func (g *Gateway) SetCfgPath(path string) {
	g.cfgPath = path
}

// ReloadConfig re-reads config from disk and hot-swaps runtime components
// (agents, constraints, rate limiter, webhooks). LLM queue is rebuilt externally
// via the returned config so the caller can wire OnResult callbacks.
// Returns the new config (nil if reload failed).
func (g *Gateway) ReloadConfig() *config.Config {
	if g.cfgPath == "" {
		g.logger.Warn("config reload skipped: no config path set")
		return nil
	}
	newCfg, err := config.Load(g.cfgPath)
	if err != nil {
		g.logger.Error("config reload failed", "error", err)
		return nil
	}

	// Swap config pointer
	g.cfg = newCfg

	// Rebuild constraint maps
	agentConstraints, agentChainRules := buildConstraintMaps(newCfg)
	g.constraintChecker = NewConstraintChecker(agentConstraints, agentChainRules)

	// Rebuild rate limiter with new settings
	g.rateLimiter = proxy.NewRateLimiter(newCfg.RateLimit.PerAgent, newCfg.RateLimit.WindowS)

	// Rebuild webhooks
	g.webhooks = proxy.NewWebhookNotifier(newCfg.Webhooks, g.logger)

	// Clear auto-registered agents cache so new config agents take effect
	g.registeredMu.Lock()
	g.registeredAgents = make(map[string]bool)
	g.registeredMu.Unlock()

	g.logger.Info("config reloaded",
		"agents", len(newCfg.Agents),
		"llm_enabled", newCfg.LLM.Enabled,
	)
	return newCfg
}

// autoRegisterAgent adds a new agent to the config if it doesn't exist.
// Called when an unknown _oktsec_agent name is seen in traffic.
func (g *Gateway) autoRegisterAgent(name string) {
	var needSave bool

	g.registeredMu.Lock()
	if g.registeredAgents[name] {
		g.registeredMu.Unlock()
		return
	}
	if _, exists := g.cfg.Agents[name]; exists {
		g.registeredAgents[name] = true
		g.registeredMu.Unlock()
		return
	}

	// Cap to prevent unbounded growth from malicious agent names
	if len(g.registeredAgents) >= 500 {
		g.registeredMu.Unlock()
		g.logger.Warn("auto-register cap reached, ignoring new agent", "name", name)
		return
	}

	// Auto-register with permissive defaults
	if g.cfg.Agents == nil {
		g.cfg.Agents = make(map[string]config.Agent)
	}
	g.cfg.Agents[name] = config.Agent{
		CanMessage:     []string{"*"},
		BlockedContent: []string{},
		ScanProfile:    config.ScanProfileContentAware,
		Description:    "Auto-registered from gateway traffic",
		CreatedBy:      "gateway",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Location:       "gateway/mcp",
	}
	g.registeredAgents[name] = true
	needSave = g.cfgPath != ""
	g.registeredMu.Unlock()

	g.logger.Info("auto-registered agent", "name", name)

	// Persist outside lock to avoid blocking the hot path
	if needSave {
		if err := g.cfg.Save(g.cfgPath); err != nil {
			g.logger.Warn("failed to save auto-registered agent", "name", name, "error", err)
		}
	}
}

// logAudit writes an audit entry for a gateway tool call.
// Optional extra strings: first is delegation_chain_hash.
func (g *Gateway) logAudit(msgID, agent, tool, status, decision, findingsJSON, toolArgs, sessionID string, start time.Time, extra ...string) {
	var delHash, delChain string
	if len(extra) > 0 {
		delHash = extra[0]
	}
	if len(extra) > 1 {
		delChain = extra[1]
	}
	g.audit.Log(audit.Entry{
		ID:                  msgID,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		FromAgent:           agent,
		ToAgent:             agent,
		ToolName:            tool,
		ContentHash:         "",
		Status:              status,
		RulesTriggered:      findingsJSON,
		PolicyDecision:      decision,
		LatencyMs:           time.Since(start).Milliseconds(),
		Intent:              toolArgs,
		SessionID:           sessionID,
		DelegationChainHash: delHash,
		DelegationChain:     delChain,
	})
}

// Scanner returns the gateway's content scanner.
func (g *Gateway) Scanner() *engine.Scanner {
	return g.scanner
}

// AuditStore returns the gateway's audit store for external wiring (e.g., LLM result callbacks).
func (g *Gateway) AuditStore() *audit.Store {
	return g.audit
}

// SetLLMQueue sets the async LLM analysis queue for the gateway.
func (g *Gateway) SetLLMQueue(q *llm.Queue) {
	g.llmQueue = q
}

// SetSignalDetector sets the triage pre-filter for LLM analysis.
func (g *Gateway) SetSignalDetector(sd *llm.SignalDetector) {
	g.signalDetector = sd
}

// SetEscalationTracker sets the LLM-driven verdict escalation tracker.
func (g *Gateway) SetEscalationTracker(t *llm.EscalationTracker) {
	g.escalationTracker = t
}

// SetHooksHandler sets the handler for /hooks/event (tool-call telemetry).
func (g *Gateway) SetHooksHandler(h http.Handler) {
	g.hooksHandler = h
}

// submitToLLM submits tool call content for async LLM analysis if configured.
func (g *Gateway) submitToLLM(agent, tool, content string, v engine.ScanVerdict, findings []engine.FindingSummary) {
	if g.llmQueue == nil || g.cfg == nil {
		g.logger.Debug("llm skip: queue or cfg nil", "queue_nil", g.llmQueue == nil, "cfg_nil", g.cfg == nil)
		return
	}

	lcfg := g.cfg.LLM
	if lcfg.MinContentLength > 0 && len(content) < lcfg.MinContentLength {
		return
	}

	// Signal detector (triage pre-filter) is sole gatekeeper if attached
	if g.signalDetector != nil {
		sig := g.signalDetector.Detect(agent, "gateway/"+tool, content, string(v))
		if !sig.ShouldAnalyze {
			return
		}
	} else {
		shouldAnalyze := false
		switch v {
		case engine.VerdictClean:
			shouldAnalyze = lcfg.Analyze.Clean
		case engine.VerdictFlag:
			shouldAnalyze = lcfg.Analyze.Flagged
		case engine.VerdictQuarantine:
			shouldAnalyze = lcfg.Analyze.Quarantined
		case engine.VerdictBlock:
			shouldAnalyze = lcfg.Analyze.Blocked
		}
		if !shouldAnalyze {
			return
		}
	}

	g.llmQueue.Submit(llm.AnalysisRequest{
		MessageID:      fmt.Sprintf("gw-%s-%d", tool, time.Now().UnixNano()),
		FromAgent:      agent,
		ToAgent:        "gateway",
		Content:        content,
		CurrentVerdict: v,
		Findings:       findings,
		Timestamp:      time.Now(),
	})
}

// toolError creates a CallToolResult with IsError=true.
func toolError(msg string) *mcp.CallToolResult {
	return mcputil.NewToolResultError(msg)
}

// summarizeToolArgs returns a compact JSON string of tool arguments for audit.
// Truncates to 512 chars to keep the audit log manageable.
func summarizeToolArgs(req *mcp.CallToolRequest) string {
	raw := req.Params.Arguments
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return ""
	}
	s := string(raw)
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// extractToolContent serializes tool name + arguments for scanning.
func extractToolContent(toolName string, req *mcp.CallToolRequest) string {
	args := mcputil.GetArguments(req.Params.Arguments)
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
		if tc, ok := c.(*mcp.TextContent); ok {
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

// injectAgentParam adds an optional _oktsec_agent property to a tool's InputSchema.
// This allows sub-agents (e.g. Claude Code custom agents) to self-identify
// so the gateway can track each agent separately in the audit log.
// buildSchemaWithAgent takes an existing InputSchema and returns a new schema
// (as map[string]any) with the _oktsec_agent property injected.
func buildSchemaWithAgent(original any) map[string]any {
	// Default empty schema
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
		"required":   []any{},
	}

	// Merge original schema if available
	if original != nil {
		raw, err := json.Marshal(original)
		if err == nil {
			var orig map[string]any
			if json.Unmarshal(raw, &orig) == nil {
				schema = orig
			}
		}
	}

	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		props = make(map[string]any)
	}

	props["_oktsec_agent"] = map[string]any{
		"type":        "string",
		"description": "REQUIRED: Your agent/role name for security audit logging. Use your specific agent name (e.g. 'cyber-news-hunter', 'vuln-researcher', 'content-writer'). If you are a sub-agent, use the name you were given when spawned.",
	}
	schema["properties"] = props

	required, _ := schema["required"].([]any)
	required = append(required, "_oktsec_agent")
	schema["required"] = required

	return schema
}

// extractAndStripAgentParam extracts _oktsec_agent from the tool call arguments,
// removes it so backends don't see it, and returns the agent name.
func extractAndStripAgentParam(req *mcp.CallToolRequest) string {
	args := mcputil.GetArguments(req.Params.Arguments)
	if args == nil {
		return ""
	}
	v, ok := args["_oktsec_agent"]
	if !ok {
		return ""
	}
	name, _ := v.(string)
	if name == "" {
		return ""
	}

	// Remove from arguments before forwarding to backend
	delete(args, "_oktsec_agent")
	raw, err := json.Marshal(args)
	if err == nil {
		req.Params.Arguments = raw
	}

	return name
}


// buildConstraintMaps extracts per-agent tool constraints and chain rules
// from the config, converting config types to gateway types.
func buildConstraintMaps(cfg *config.Config) (map[string][]ToolConstraint, map[string][]ToolChainRule) {
	if len(cfg.Agents) == 0 {
		return nil, nil
	}

	var agentConstraints map[string][]ToolConstraint
	var agentChainRules map[string][]ToolChainRule

	for name, agent := range cfg.Agents {
		if len(agent.ToolConstraints) > 0 {
			if agentConstraints == nil {
				agentConstraints = make(map[string][]ToolConstraint)
			}
			constraints := make([]ToolConstraint, len(agent.ToolConstraints))
			for i, tc := range agent.ToolConstraints {
				constraints[i] = ToolConstraint{
					Tool:             tc.Tool,
					MaxResponseBytes: tc.MaxResponseBytes,
					CooldownSecs:     tc.CooldownSecs,
				}
				if len(tc.Parameters) > 0 {
					constraints[i].Parameters = make(map[string]ParamConstraint)
					for pName, pc := range tc.Parameters {
						constraints[i].Parameters[pName] = ParamConstraint{
							AllowedPatterns: pc.AllowedPatterns,
							BlockedPatterns: pc.BlockedPatterns,
							MaxLength:       pc.MaxLength,
						}
					}
				}
			}
			agentConstraints[name] = constraints
		}

		if len(agent.ToolChainRules) > 0 {
			if agentChainRules == nil {
				agentChainRules = make(map[string][]ToolChainRule)
			}
			rules := make([]ToolChainRule, len(agent.ToolChainRules))
			for i, cr := range agent.ToolChainRules {
				rules[i] = ToolChainRule{
					If:           cr.If,
					Then:         cr.Then,
					CooldownSecs: cr.CooldownSecs,
				}
			}
			agentChainRules[name] = rules
		}
	}

	return agentConstraints, agentChainRules
}

// verdictToGateway maps a verdict to (status, policyDecision).
var verdictToGateway = verdict.ToAuditStatus

// verifyDelegationHeader decodes and verifies a base64-encoded delegation chain
// from the X-Oktsec-Delegation HTTP header. Uses the gateway's keystore to
// resolve public keys for each delegator in the chain.
func (g *Gateway) verifyDelegationHeader(header string) identity.ChainVerifyResult {
	data, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return identity.ChainVerifyResult{Valid: false, Reason: "invalid base64 encoding"}
	}

	var chain identity.DelegationChain
	if err := json.Unmarshal(data, &chain); err != nil {
		return identity.ChainVerifyResult{Valid: false, Reason: "invalid chain JSON"}
	}

	// Resolve public keys from the identity keystore
	resolver := func(agent string) ed25519.PublicKey {
		if g.cfg.Identity.KeysDir == "" {
			return nil
		}
		ks := identity.NewKeyStore()
		_ = ks.LoadFromDir(g.cfg.Identity.KeysDir)
		pub, ok := ks.Get(agent)
		if !ok {
			return nil
		}
		return pub
	}

	return identity.VerifyChain(chain, resolver)
}

