package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/identity/resolve"
	"github.com/oktsec/oktsec/internal/llm"
	"github.com/oktsec/oktsec/internal/mcputil"
	"github.com/oktsec/oktsec/internal/netutil"
	"github.com/oktsec/oktsec/internal/policy"
	"github.com/oktsec/oktsec/internal/proxy"
	"github.com/oktsec/oktsec/internal/verdict"
)

// activityWriter is the narrow projection of activity.Store the gateway
// uses. Defined locally so tests can inject a stub without depending on
// the full Store interface (Query, ListByCoverageCell, etc.). Production
// passes an *activity.SQLStore; tests pass a recorder.
type activityWriter interface {
	Insert(ctx context.Context, e activity.Event) error
}

// Version is set from the CLI at startup (via ldflags).
var Version = "dev"

type contextKey string

const agentContextKey contextKey = "oktsec-agent"
const sessionContextKey contextKey = "oktsec-session"
const delegationContextKey contextKey = "oktsec-delegation"
const reportedActorContextKey contextKey = "oktsec-reported-actor"
const authMethodContextKey contextKey = "oktsec-auth-method"
const trustLevelContextKey contextKey = "oktsec-trust-level"

// requestIdentity is the identity bundle the gateway carries from the
// auth middleware down to logAudit. Built once per request via
// identityFromContext so handlers do not have to reach into context for
// each field — and so audit calls cannot accidentally pass the wrong
// principal to the security pipeline.
//
// PrincipalID is the only identity policy code may use. AuthMethod and
// TrustLevel record HOW it was established; ReportedActor is the
// display-only actor the surface saw alongside it (subagent name,
// payload field, hook body) and never affects policy.
type requestIdentity struct {
	PrincipalID   string
	AuthMethod    string
	TrustLevel    string
	ReportedActor string
}

// identityFromContext lifts the values the auth middleware put into ctx
// into a single struct. Empty fields are returned as "" — handlers and
// logAudit treat that as "no information" rather than failing.
func identityFromContext(ctx context.Context) requestIdentity {
	var id requestIdentity
	if v, ok := ctx.Value(agentContextKey).(string); ok {
		id.PrincipalID = v
	}
	if v, ok := ctx.Value(authMethodContextKey).(string); ok {
		id.AuthMethod = v
	}
	if v, ok := ctx.Value(trustLevelContextKey).(string); ok {
		id.TrustLevel = v
	}
	if v, ok := ctx.Value(reportedActorContextKey).(string); ok {
		id.ReportedActor = v
	}
	return id
}

// toolMapping maps a frontend tool name to its backend.
type toolMapping struct {
	BackendName    string
	OriginalName   string
	Backend        *Backend
	Classification ToolClassification
}

// ToolInfo holds information about a gateway tool for external consumers.
type ToolInfo struct {
	FrontendName   string
	BackendName    string
	OriginalName   string
	Description    string
	Classification ToolClassification
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
	rateLimiter       proxy.RateStore
	concurrency       *concurrencyLimiter
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

	// onReady is invoked exactly once after the listener has been
	// successfully bound (and cfg.Gateway.Port has been mutated to the
	// actual port). The dashboard uses this hook to flip
	// "Configured Port" to "Listening on" only after the gateway is
	// truly listening, instead of optimistically marking the port
	// live before bind succeeds. nil is the default no-op.
	onReady func()

	// resolver and resolverConfig together decide which Principal a
	// request belongs to. The resolver is always non-nil — even when no
	// principals are configured the store is empty rather than nil so the
	// adapter never has to nil-check before each Resolve.
	resolver       resolve.Resolver
	resolverConfig resolve.Config
	requireAuth    bool // derived from cfg.Gateway.RequireAuth + deployment profile

	// activity emits one normalized activity event per audit row so the
	// dashboard coverage matrix can show real evidence behind each cell.
	// May be nil when the audit store does not expose a *sql.DB (e.g.,
	// some test scaffolds) or when activity migration failed at startup —
	// in either case the gateway logs only audit and the dashboard falls
	// back to its audit-backed last-seen reader.
	activity activityWriter
}

// authMiddleware runs the identity resolver for every gateway request,
// fails closed when require_auth is on, and exposes the resolved Principal
// (plus reported actor and auth method) to downstream handlers via the
// request context. Extracted for testability so identity contracts can be
// exercised without spinning up the full MCP backend stack.
func (g *Gateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evidence := resolve.Evidence{
			Surface:     resolve.SurfaceMCPHTTP,
			Header:      r.Header,
			RemoteAddr:  r.RemoteAddr,
			ConfigAgent: r.Header.Get("X-Oktsec-Agent"),
		}
		result, err := g.resolver.Resolve(r.Context(), g.resolverConfig, evidence)
		if err != nil {
			// Resolver should not error on well-formed paths today, but
			// any transport-style failure fails closed rather than
			// continuing with no identity.
			http.Error(w, "identity resolver error", http.StatusInternalServerError)
			return
		}
		if g.requireAuth {
			if trustErr := result.RequireMinimumTrust(resolve.TrustAuthenticated); trustErr != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="oktsec gateway"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		ctx := context.WithValue(r.Context(), agentContextKey, result.Principal.ID)
		ctx = context.WithValue(ctx, authMethodContextKey, string(result.Principal.AuthMethod))
		ctx = context.WithValue(ctx, trustLevelContextKey, string(result.Principal.TrustLevel))
		if result.ReportedActor.ID != "" {
			ctx = context.WithValue(ctx, reportedActorContextKey, result.ReportedActor.ID)
		}
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			ctx = context.WithValue(ctx, sessionContextKey, sid)
		}
		if del := r.Header.Get("X-Oktsec-Delegation"); del != "" {
			ctx = context.WithValue(ctx, delegationContextKey, del)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// gatewaySurfacePolicy derives the per-surface identity contract for the
// MCP gateway. Same helper (resolve.DerivePolicy) will be used by hooks
// and the forward proxy when those surfaces migrate; the gateway just
// fills in its own AuthMethods / TrustedLoopbackHeaders / RequireAuth
// from cfg.Gateway.
func gatewaySurfacePolicy(cfg *config.Config) resolve.SurfacePolicy {
	return resolve.DerivePolicy(resolve.SurfaceAuthInput{
		Surface:                 resolve.SurfaceMCPHTTP,
		Profile:                 resolve.ProfileFromString(cfg.Deployment.Profile),
		RequireSurfaceAuth:      cfg.Deployment.RequireSurfaceAuth,
		RequireAuthOverride:     cfg.Gateway.RequireAuth,
		AuthMethods:             cfg.Gateway.AuthMethods,
		TrustedLoopbackHeaders:  cfg.Gateway.TrustedLoopbackHeaders,
		ReportedActorHeaderName: "X-Oktsec-Reported-Actor",
		AllowedTokenTypes:       []resolve.TokenType{resolve.TokenTypeGatewayBearer},
	})
}

// configPrincipalsFor projects cfg.Identity.Principals into the
// resolve-package shape so the resolver does not import config.
func configPrincipalsFor(cfg *config.Config) []resolve.ConfigPrincipal {
	out := make([]resolve.ConfigPrincipal, 0, len(cfg.Identity.Principals))
	for _, p := range cfg.Identity.Principals {
		toks := make([]resolve.ConfigToken, 0, len(p.Tokens))
		for _, t := range p.Tokens {
			toks = append(toks, resolve.ConfigToken{
				ID: t.ID, Type: t.Type, Hash: t.Hash,
				CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt,
			})
		}
		out = append(out, resolve.ConfigPrincipal{
			ID: p.ID, DisplayName: p.DisplayName, Kind: p.Kind,
			WorkspaceID: p.WorkspaceID, AllowedSurfaces: p.AllowedSurfaces,
			Tokens:  toks,
			Context: configPrincipalContext(p.Context),
		})
	}
	return out
}

// configPrincipalContext lifts the YAML PrincipalContextConfig into the
// resolver-side neutral context. Empty in, empty out.
func configPrincipalContext(c config.PrincipalContextConfig) resolve.ConfigPrincipalContext {
	return resolve.ConfigPrincipalContext{
		Issuer:     c.Issuer,
		Subject:    c.Subject,
		Audience:   c.Audience,
		ClientID:   c.ClientID,
		TenantID:   c.TenantID,
		Groups:     c.Groups,
		Scopes:     c.Scopes,
		Provider:   c.Provider,
		Source:     c.Source,
		Verified:   c.Verified,
		ExpiresAt:  c.ExpiresAt,
		ClaimsHash: c.ClaimsHash,
	}
}

// buildResolver constructs the resolver/store the gateway uses for every
// request. The store is always non-nil — even when no principals are
// configured the bucket is empty and Lookup just returns ErrNoToken — so
// the request path never has to nil-check before resolving.
func buildResolver(cfg *config.Config) resolve.Resolver {
	principals := resolve.PrincipalsFromConfig(configPrincipalsFor(cfg))
	store := resolve.NewMemoryTokenStoreWithClock(principals, nil)
	return resolve.NewDefaultResolver(store, nil)
}

// buildGatewayActivity constructs the activity store the gateway uses
// for dual-write. Lives in NewGateway (and newGatewayForTest) so the
// gateway is wired exactly the same whether oktsec runs standalone
// (`oktsec gateway`) or as part of `oktsec serve`. Returns nil when the
// audit store does not expose a *sql.DB or migration fails: callers
// continue with audit-only logging and the coverage matrix falls back
// to its audit-backed reader.
func buildGatewayActivity(auditStore *audit.Store, logger *slog.Logger) activityWriter {
	if auditStore == nil {
		return nil
	}
	db := auditStore.DB()
	if db == nil {
		return nil
	}
	dialect := activity.Dialect(auditStore.DialectName())
	if dialect == "" {
		// Unknown dialect; do not invent a default. Coverage will fall
		// back to the audit-backed last-seen reader.
		logger.Warn("activity store skipped: audit store reports unknown dialect")
		return nil
	}
	if err := activity.Migrate(db, dialect); err != nil {
		logger.Warn("activity store skipped: migrate failed", "error", err)
		return nil
	}
	return activity.NewSQLStore(db, dialect)
}

// principalIDOrUnknown enforces activity.Event's PrincipalID-required
// invariant for surfaces that allow anonymous local telemetry (hooks).
// The gateway never produces an empty principal in normal flow but
// handlers run during startup edge cases where the field can be empty.
func principalIDOrUnknown(id string) string {
	if id == "" {
		return "unknown"
	}
	return id
}

// activityInsertTimeout bounds the dual-write so a stalled DB cannot
// pin a goroutine indefinitely. 2s is generous for a single insert on
// SQLite WAL and short enough that a misbehaving Postgres does not fan
// out goroutines forever.
const activityInsertTimeout = 2 * time.Second

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
		// Wire archive_dir so the auto-purge loop honors retention safely.
		auditStore.SetArchiveDir(cfg.Quarantine.ArchiveDir)
	}

	webhooks := proxy.NewWebhookNotifier(cfg.Webhooks, logger)
	rateLimiter := proxy.NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS)

	agentConstraints, agentChainRules := buildConstraintMaps(cfg)

	policy := gatewaySurfacePolicy(cfg)
	return &Gateway{
		cfg:               cfg,
		backends:          make(map[string]*Backend),
		toolMap:           make(map[string]toolMapping),
		scanner:           scanner,
		audit:             auditStore,
		webhooks:          webhooks,
		rateLimiter:       rateLimiter,
		concurrency:       newConcurrencyLimiter(cfg),
		policyEnforcer:    NewToolPolicyEnforcer(),
		constraintChecker: NewConstraintChecker(agentConstraints, agentChainRules),
		logger:            logger,
		registeredAgents:  make(map[string]bool),
		resolver:          buildResolver(cfg),
		resolverConfig:    policy.ResolverConfig,
		requireAuth:       policy.RequireAuth,
		activity:          buildGatewayActivity(auditStore, logger),
	}, nil
}

// newGatewayForTest creates a gateway with injected dependencies (no real scanner/audit).
func newGatewayForTest(cfg *config.Config, scanner *engine.Scanner, auditStore *audit.Store, logger *slog.Logger) *Gateway {
	agentConstraints, agentChainRules := buildConstraintMaps(cfg)
	policy := gatewaySurfacePolicy(cfg)
	return &Gateway{
		cfg:               cfg,
		backends:          make(map[string]*Backend),
		toolMap:           make(map[string]toolMapping),
		scanner:           scanner,
		audit:             auditStore,
		webhooks:          proxy.NewWebhookNotifier(nil, logger),
		rateLimiter:       proxy.NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS),
		concurrency:       newConcurrencyLimiter(cfg),
		policyEnforcer:    NewToolPolicyEnforcer(),
		constraintChecker: NewConstraintChecker(agentConstraints, agentChainRules),
		logger:            logger,
		registeredAgents:  make(map[string]bool),
		resolver:          buildResolver(cfg),
		resolverConfig:    policy.ResolverConfig,
		requireAuth:       policy.RequireAuth,
		activity:          buildGatewayActivity(auditStore, logger),
	}
}

// SetActivityStore lets callers inject a custom activityWriter (e.g., a
// recorder in tests, or a future shared store wired by `oktsec serve`).
// Pass nil to disable activity dual-write entirely. Safe to call before
// the gateway starts serving; not safe to swap mid-flight.
func (g *Gateway) SetActivityStore(w activityWriter) {
	g.activity = w
}

// Start connects to all backends, discovers tools, and starts the HTTP server.
// It blocks until the server is shut down.
func (g *Gateway) Start(ctx context.Context) error {
	// Dependency manifest rug-pull detection: hash manifests before
	// connecting backends so operators see warnings before any code runs.
	if g.cfg.Gateway.DepCheck {
		store := newDepHashStore(defaultDepHashPath())
		for name, srv := range g.cfg.MCPServers {
			if srv.WorkingDir == "" {
				continue
			}
			changes := store.Check(name, srv.WorkingDir)
			for _, c := range changes {
				if c.OldHash == "" {
					g.logger.Info("dependency baseline recorded",
						"server", c.ServerName, "file", c.File)
				} else {
					g.logger.Warn("dependency manifest changed",
						"server", c.ServerName, "file", c.File,
						"old", c.OldHash[:12], "new", c.NewHash[:12])
				}
			}
		}
		if err := store.Save(); err != nil {
			g.logger.Warn("failed to save dependency hashes", "error", err)
		}
	}

	// Resolve the forward proxy port for egress sandboxing.
	proxyPort := g.cfg.ForwardProxy.Port
	if proxyPort == 0 {
		proxyPort = 8083
	}

	// Connect backends
	for name, cfg := range g.cfg.MCPServers {
		if cfg.EgressSandbox && !g.cfg.ForwardProxy.Enabled {
			g.logger.Warn("egress_sandbox enabled but forward_proxy is not; child HTTP traffic may fail",
				"server", name)
		}
		b := NewBackend(name, cfg, g.logger)
		b.SetProxyPort(proxyPort)
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

	agentMiddleware := g.authMiddleware(streamable)

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
	// Listener is bound and cfg.Gateway.Port now holds the actual
	// port. Notify the readiness callback (if set) so callers like
	// the dashboard can flip a "live listener" flag — but only now,
	// not when NewGateway returns and not before the bind succeeds.
	if g.onReady != nil {
		g.onReady()
	}

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

	// Count tool name occurrences to detect conflicts. A backend tool whose name
	// is the reserved deny-all sentinel is NEVER registered: the sentinel is a
	// control marker, not a callable tool, and registering it would let a backend
	// smuggle in a callable tool with the reserved name (defeating the deny-all
	// representation). Reject it here at the single discovery chokepoint with an
	// explicit warning so it is excluded, never silently callable.
	nameCounts := make(map[string]int)
	for _, b := range g.backends {
		for _, t := range b.Tools {
			if t.Name == config.DenyAllToolsSentinel {
				continue
			}
			nameCounts[t.Name]++
		}
	}

	for backendName, b := range g.backends {
		for _, t := range b.Tools {
			if t.Name == config.DenyAllToolsSentinel {
				g.logger.Warn("backend tool uses reserved deny-all sentinel name; excluding from gateway",
					"backend", backendName, "tool", t.Name)
				continue
			}
			frontendName := t.Name
			if nameCounts[t.Name] > 1 {
				frontendName = backendName + "_" + t.Name
			}
			// A namespaced frontend name could ALSO collide with the reserved
			// sentinel (e.g. backend "__oktsec" + tool "deny_all__" -> the sentinel).
			// The handler keys deny-all on OriginalName, so a sentinel-named frontend
			// would still be callable; exclude it here too.
			if frontendName == config.DenyAllToolsSentinel {
				g.logger.Warn("namespaced tool name collides with reserved deny-all sentinel; excluding from gateway",
					"backend", backendName, "tool", t.Name, "frontend", frontendName)
				continue
			}
			g.toolMap[frontendName] = toolMapping{
				BackendName:    backendName,
				OriginalName:   t.Name,
				Backend:        b,
				Classification: ClassifyTool(t.Name, t.Description),
			}
		}
	}
	return nil
}

// ListToolInfo returns classification info for all tools in the gateway.
func (g *Gateway) ListToolInfo() []ToolInfo {
	var tools []ToolInfo
	for frontendName, m := range g.toolMap {
		desc := ""
		for _, t := range m.Backend.Tools {
			if t.Name == m.OriginalName {
				desc = t.Description
				break
			}
		}
		tools = append(tools, ToolInfo{
			FrontendName:   frontendName,
			BackendName:    m.BackendName,
			OriginalName:   m.OriginalName,
			Description:    desc,
			Classification: m.Classification,
		})
	}
	return tools
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

		// 1. Lift the resolved Principal + provenance the auth middleware
		// stored on ctx into a single struct. Every audit row written for
		// this request will carry the same identity bundle, so the policy
		// principal cannot drift from what the audit reader sees.
		id := identityFromContext(ctx)
		if id.PrincipalID == "" {
			id.PrincipalID = "unknown"
		}
		agent := id.PrincipalID

		// 1a. Extract sub-agent identity from tool arguments. The
		// _oktsec_agent param is metadata for audit only — it never
		// becomes the policy principal regardless of value. If the
		// payload supplied a sub-agent it is the most specific reported
		// actor we have, so it overrides whatever the surface header
		// declared.
		policyAgent := agent
		subAgent := extractAndStripAgentParam(req)
		if subAgent != "" {
			g.autoRegisterAgent(subAgent)
			id.ReportedActor = subAgent
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
		var delegationAllowedTools []string
		if delHeader, _ := ctx.Value(delegationContextKey).(string); delHeader != "" {
			chainResult := g.verifyDelegationHeader(delHeader)
			if chainResult.Valid {
				// Enforce per-agent delegation depth cap. Crossing this line
				// is how a rogue agent tries to fan out into a sub-tree of
				// delegated children; we stop it at the gateway.
				if maxDepth := policy.ResolveDelegationDepth(g.cfg, policyAgent); maxDepth > 0 && chainResult.Depth > maxDepth {
					g.logger.Warn("delegation depth exceeded",
						"agent", agent, "depth", chainResult.Depth, "max", maxDepth)
					g.logAudit(msgID, id, m.OriginalName, audit.StatusBlocked, audit.DecisionDelegationDepthExceeded, "[]", toolArgs, sessionID, start)
					return toolError(fmt.Sprintf("delegation depth %d exceeds max %d", chainResult.Depth, maxDepth)), nil
				}
				delegationChainHash = chainResult.ChainHash
				delegationChainSummary = chainResult.Root + " -> " + chainResult.Delegate
				delegationAllowedTools = chainResult.Tools
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
		if !g.rateLimiter.Allow(policyAgent) {
			g.logAudit(msgID, id, m.OriginalName, audit.StatusRejected, audit.DecisionRateLimited, "[]", toolArgs, sessionID, start)
			return toolError("rate limit exceeded"), nil
		}

		// 2b. Per-agent concurrency slot. Held through scan + backend call so
		// a single agent can't open N parallel sockets against the same tool.
		release, err := g.concurrency.acquire(ctx, policyAgent)
		if err != nil {
			g.logAudit(msgID, id, m.OriginalName, audit.StatusRejected, audit.DecisionConcurrencyExceeded, "[]", toolArgs, sessionID, start)
			return toolError("concurrency limit exceeded"), nil
		}
		defer release()

		// 3. Tool allowlist check.
		// The reserved deny-all sentinel is never a callable tool name, for ANY
		// principal (even one with no agent config). Deny it unconditionally before
		// the agent lookup so a sentinel-named tool can never execute. Gateway
		// discovery already excludes such a backend tool, so this is defense in
		// depth that also closes the no-agent-config path.
		if m.OriginalName == config.DenyAllToolsSentinel {
			g.logAudit(msgID, id, m.OriginalName, audit.StatusBlocked, audit.DecisionToolNotAllowed, "[]", toolArgs, sessionID, start)
			return toolError(fmt.Sprintf("tool %q not allowed for agent %q", m.OriginalName, agent)), nil
		}
		if agentCfg, ok := g.cfg.Agents[policyAgent]; ok {
			if agentCfg.Suspended {
				g.logAudit(msgID, id, m.OriginalName, audit.StatusRejected, audit.DecisionAgentSuspended, "[]", toolArgs, sessionID, start)
				return toolError("agent suspended"), nil
			}
			// Deny-all sentinel allowlist is special-cased BEFORE name matching so it
			// can never execute as a tool: when the agent's allowlist is the lone
			// deny-all sentinel, deny EVERY call (the sentinel is a control marker,
			// never a matchable name).
			if config.IsDenyAllTools(agentCfg.AllowedTools) {
				g.logAudit(msgID, id, m.OriginalName, audit.StatusBlocked, audit.DecisionToolNotAllowed, "[]", toolArgs, sessionID, start)
				return toolError(fmt.Sprintf("tool %q not allowed for agent %q", m.OriginalName, agent)), nil
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
					g.logAudit(msgID, id, m.OriginalName, audit.StatusBlocked, audit.DecisionToolNotAllowed, "[]", toolArgs, sessionID, start)
					return toolError(fmt.Sprintf("tool %q not allowed for agent %q", m.OriginalName, agent)), nil
				}
			}
		}

		// 3b. Tool policy enforcement (spending limits, rate limits, approval thresholds)
		if agentCfg, ok := g.cfg.Agents[policyAgent]; ok && agentCfg.ToolPolicies != nil {
			if policy, hasPolicy := agentCfg.ToolPolicies[m.OriginalName]; hasPolicy {
				amount := ExtractAmount(mcputil.GetArguments(req.Params.Arguments))
				result := g.policyEnforcer.Check(policyAgent, m.OriginalName, amount, policy)
				if !result.Allowed {
					status := audit.StatusBlocked
					if result.Decision == "quarantine_approval" {
						status = audit.StatusQuarantined
					}
					g.logAudit(msgID, id, m.OriginalName, status, result.Decision, "[]", toolArgs, sessionID, start)
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
			result := g.constraintChecker.CheckToolCall(policyAgent, m.OriginalName, params)
			if !result.Allowed {
				g.logAudit(msgID, id, m.OriginalName, audit.StatusBlocked, audit.DecisionConstraintViolated, "[]", toolArgs, sessionID, start)
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
			g.logAudit(msgID, id, m.OriginalName, audit.StatusDelivered, audit.DecisionScanError, "[]", toolArgs, sessionID, start)
			// Forward on scan error — fail open
		}

		if outcome == nil {
			outcome = &engine.ScanOutcome{Verdict: engine.VerdictClean}
		}

		// 6. Apply tool-scoped rule overrides (PostAguara: built-in
		// exemptions already applied by Aguara via WithToolName).
		verdict.ApplyToolScopedOverridesPostAguara(g.cfg.Rules, outcome, m.OriginalName)

		// 6b. Apply agent scan profile if explicitly configured.
		if agentCfg, ok := g.cfg.Agents[policyAgent]; ok && agentCfg.ScanProfile != "" {
			verdict.ApplyScanProfile(agentCfg.ScanProfile, outcome, m.OriginalName)
		}

		// If all findings were removed by tool scoping, reset to clean.
		if len(outcome.Findings) == 0 {
			outcome.Verdict = engine.VerdictClean
		}

		// 7. Apply blocked content
		if agentCfg, ok := g.cfg.Agents[policyAgent]; ok {
			verdict.ApplyBlockedContent(agentCfg, outcome)
		}

		// 7b. LLM-driven agent escalation (async feedback loop)
		if g.escalationTracker != nil && g.escalationTracker.IsEscalated(policyAgent) {
			outcome.Verdict = verdict.EscalateOneLevel(outcome.Verdict)
		}

		// 8. Determine verdict
		findingsJSON := verdict.EncodeFindings(outcome.Findings)
		status, decision := verdictToGateway(outcome.Verdict)

		// 9. Audit log (with delegation chain if verified)
		g.logAudit(msgID, id, m.OriginalName, status, decision, findingsJSON, toolArgs, sessionID, start, delegationChainHash, delegationChainSummary)

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

		// 11. Export testcase for blocked/quarantined tool calls
		if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
			if g.cfg.Audit.ExportBlocked {
				for _, f := range outcome.Findings {
					_, _ = audit.ExportTestcase(audit.Testcase{
						RuleID:    f.RuleID,
						Type:      "true_positive",
						Source:    "production",
						Timestamp: time.Now().UTC().Format(time.RFC3339),
						Agent:     agent,
						Tool:      m.OriginalName,
						Content:   content,
						Severity:  f.Severity,
						Verdict:   string(outcome.Verdict),
					})
				}
			}
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
		if agentCfg, ok := g.cfg.Agents[policyAgent]; ok && agentCfg.ToolPolicies != nil {
			if _, hasPolicy := agentCfg.ToolPolicies[m.OriginalName]; hasPolicy {
				amount := ExtractAmount(mcputil.GetArguments(req.Params.Arguments))
				g.policyEnforcer.Record(policyAgent, m.OriginalName, amount)
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

		// 14. Verify response stays within delegated scope (best-effort)
		if delegationChainSummary != "" && g.cfg.Gateway.VerifyDelegationScope && result != nil {
			if violation := checkResponseScope(result, delegationAllowedTools); violation != "" {
				g.logger.Warn("subagent response outside delegated scope",
					"agent", agent, "tool", m.OriginalName, "violation", violation)
				g.logAudit(msgID, id, m.OriginalName, audit.StatusDelivered,
					audit.DecisionDelegationScopeViolation, "[]", toolArgs, sessionID, start,
					delegationChainHash, delegationChainSummary)
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
//
// Honours GatewayConfig.DisableAutoRegister: when set, unknown agents
// never reach the config — the caller falls back to the header agent
// (which went through the same check at a higher level). Use this in
// production or during controlled customer walkthroughs where the
// agent roster should be explicit.
func (g *Gateway) autoRegisterAgent(name string) {
	if g.cfg.Gateway.DisableAutoRegister {
		return
	}
	// A name that fails public principal-name validation must not be
	// auto-registered. Auto-register fires on external traffic, so we
	// also reject reserved (leading-underscore) names to prevent
	// collision with the internal _proxy signing principal.
	if err := identity.ValidatePublicPrincipalName(name); err != nil {
		g.logger.Warn("rejecting auto-register for unsafe agent name", "name", name, "error", err)
		return
	}
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
// logAudit writes one audit entry and emits the matching activity
// event. The caller passes the resolved requestIdentity so the audit
// row carries the same Principal that drove the policy decision, plus
// the AuthMethod / TrustLevel / ReportedActor provenance the resolver
// established.
//
// FromAgent and ToAgent both equal id.PrincipalID — historical: the
// gateway logs every tool call as a self-edge from the principal. Other
// surfaces (agent message API) populate ToAgent differently and call
// audit.Log directly.
//
// emitGatewayActivity runs after the audit insert so every audit row
// the gateway writes has a paired activity event. Activity emission is
// async with a short timeout: a slow or failing activity store cannot
// affect the request latency or the security decision.
func (g *Gateway) logAudit(msgID string, id requestIdentity, tool, status, decision, findingsJSON, toolArgs, sessionID string, start time.Time, extra ...string) {
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
		FromAgent:           id.PrincipalID,
		ToAgent:             id.PrincipalID,
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
		AuthMethod:          id.AuthMethod,
		PrincipalTrustLevel: id.TrustLevel,
		ReportedActor:       id.ReportedActor,
	})
	g.emitGatewayActivity(msgID, id, tool, status, decision, sessionID)
}

// emitGatewayActivity writes one activity event correlated to the
// audit row just logged. Runs in a fresh background context with a
// bounded timeout so a slow DB cannot delay the request handler.
// Insert errors are logged at warn — they never affect the policy
// decision or the audit row.
//
// The activity event uses a fresh UUID so two audit rows with the
// same msgID (rare, but possible on certain post-decision paths) do
// not collide on the activity primary key. Correlation back to the
// audit row goes through AuditEntryID.
func (g *Gateway) emitGatewayActivity(msgID string, id requestIdentity, tool, status, decision, sessionID string) {
	if g.activity == nil {
		return
	}
	ev := activity.Event{
		ID:                  uuid.NewString(),
		Timestamp:           time.Now().UTC(),
		PrincipalID:         principalIDOrUnknown(id.PrincipalID),
		ReportedActor:       id.ReportedActor,
		AuthMethod:          id.AuthMethod,
		PrincipalTrustLevel: id.TrustLevel,
		Surface:             activity.SurfaceMCPHTTP,
		EventType:           activity.EventMCPToolCall,
		EvidenceType:        activity.EvidenceGateway,
		SessionID:           sessionID,
		AuditEntryID:        msgID,
		Status:              status,
		PolicyDecision:      decision,
		CoverageMode:        activity.CoverageFromAuthMethod(id.AuthMethod),
		Confidence:          activity.ConfidenceFromAuthMethod(id.AuthMethod),
		ResourceType:        "mcp_tool",
		ResourceLabel:       tool,
		ResourceID:          tool,
	}
	go func() {
		// Detached context: the request context can be cancelled by the
		// time the goroutine runs (client closed, response written), and
		// activity should still land if the DB is reachable.
		ctx, cancel := context.WithTimeout(context.Background(), activityInsertTimeout)
		defer cancel()
		if err := g.activity.Insert(ctx, ev); err != nil {
			g.logger.Warn("activity insert failed", "error", err, "msg_id", msgID, "surface", "mcp_http")
		}
	}()
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

// SetReadyCallback registers a function the gateway calls exactly
// once after its listener is bound (and cfg.Gateway.Port has been
// mutated to the actual port). Set it before Start; later calls
// silently overwrite the callback but the contract is "set once
// before Start, fires once during Start". Use this to gate any
// dashboard/UI label that should only claim "live listener" when
// the bind actually succeeded.
func (g *Gateway) SetReadyCallback(fn func()) {
	g.onReady = fn
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

// toolExecutionIndicators are common tool/action names that may appear in
// backend responses indicating which operations the subagent performed.
// Matching is case-insensitive and heuristic (best-effort detection).
var toolExecutionIndicators = []string{
	"bash", "shell", "exec", "execute", "terminal",
	"write", "edit", "read", "glob", "grep",
	"delete", "remove", "mkdir", "chmod", "chown",
	"curl", "wget", "fetch", "http_request",
	"sql", "query", "database",
	"send_email", "send_message", "notify",
	"deploy", "publish", "release",
}

// checkResponseScope checks if a backend response references tool executions
// outside the delegated allowed tools list. This is a best-effort heuristic
// check on the response content -- the backend already executed the action,
// so the value is visibility and logging, not enforcement.
func checkResponseScope(result *mcp.CallToolResult, allowedTools []string) string {
	if len(allowedTools) == 0 || result == nil {
		return "" // no tool restrictions in delegation
	}

	content := extractResultContent(result)
	if content == "" {
		return ""
	}
	contentLower := strings.ToLower(content)

	// Build a set of allowed tool names (lowercased) for fast lookup
	allowedSet := make(map[string]bool, len(allowedTools))
	for _, t := range allowedTools {
		allowedSet[strings.ToLower(t)] = true
	}

	for _, indicator := range toolExecutionIndicators {
		if !strings.Contains(contentLower, indicator) {
			continue
		}
		if !allowedSet[indicator] {
			return fmt.Sprintf("response references tool '%s' not in delegated allowed tools %v", indicator, allowedTools)
		}
	}
	return ""
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

