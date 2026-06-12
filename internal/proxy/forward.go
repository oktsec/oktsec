package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity/resolve"
	"github.com/oktsec/oktsec/internal/verdict"
)

// activityWriter is the narrow projection of activity.Store the forward
// proxy uses. Defined locally so tests can inject a stub without
// depending on the full Store interface (Query, ListByCoverageCell,
// etc.). Production passes an *activity.SQLStore; tests pass a recorder.
type activityWriter interface {
	Insert(ctx context.Context, e activity.Event) error
}

// activityInsertTimeout bounds the dual-write so a stalled DB cannot
// pin a goroutine indefinitely. 2s is generous for a single insert on
// SQLite WAL and short enough that a misbehaving Postgres does not fan
// out goroutines forever. Mirrors the gateway constant.
const activityInsertTimeout = 2 * time.Second

// ForwardProxy implements an HTTP forward proxy that scans traffic with Aguara.
// It handles CONNECT tunneling (HTTPS) and plain HTTP forwarding.
type ForwardProxy struct {
	cfg           *config.ForwardProxyConfig
	scanner       *engine.Scanner
	audit         *audit.Store
	rateLimiter   RateStore
	egressEval    *EgressEvaluator
	agentLimiters map[string]RateStore
	logger        *slog.Logger
	transport     *http.Transport
	upstreamProxy bool // true when HTTP_PROXY/HTTPS_PROXY is set

	// Identity stack: same shape as the gateway. The resolver is always
	// non-nil (empty principal store when nothing is configured) so the
	// hot path never has to nil-check.
	resolver       resolve.Resolver
	resolverConfig resolve.Config
	requireAuth    bool

	// activity emits one normalized activity event per audit row so the
	// dashboard coverage matrix can show real evidence behind each
	// http_egress_proxy cell. May be nil when the audit store does not
	// expose a *sql.DB or activity migration failed at startup — in
	// either case the proxy logs only audit and the dashboard falls
	// back to its audit-backed last-seen reader.
	activity activityWriter
}

// NewForwardProxy creates a forward proxy with scanning and audit capabilities.
//
// fullCfg carries the deployment profile and identity.principals the
// resolver needs. ForwardProxyConfig stays as the per-surface knob so
// existing call sites that build cfg.ForwardProxy by hand continue to
// work — they just lose surface auth, which is the correct fail-soft
// behavior (no principal store ⇒ no tokens accepted).
func NewForwardProxy(cfg *config.ForwardProxyConfig, scanner *engine.Scanner, auditStore *audit.Store, rateLimiter RateStore, agents map[string]config.Agent, logger *slog.Logger, tb *config.TrustBoundaries, fullCfg *config.Config) *ForwardProxy {
	// When an upstream proxy is configured (e.g., inside Docker Sandbox),
	// the transport dials the proxy, not the target. Use standard dialer
	// for proxy connections; SSRF checks are applied at handler level.
	upstream := hasUpstreamProxy()
	dialFn := SafeDialContext
	if upstream {
		d := &net.Dialer{Timeout: 5 * time.Second}
		dialFn = d.DialContext
		logger.Info("forward proxy: upstream proxy detected, SSRF checks at handler level")
	}

	fp := &ForwardProxy{
		cfg:           cfg,
		scanner:       scanner,
		audit:         auditStore,
		rateLimiter:   rateLimiter,
		egressEval:    NewEgressEvaluator(cfg, agents, tb),
		agentLimiters: make(map[string]RateStore),
		logger:        logger,
		upstreamProxy: upstream,
		transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialFn,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	fp.resolver, fp.resolverConfig, fp.requireAuth = buildForwardProxyIdentity(cfg, fullCfg)
	fp.activity = buildForwardProxyActivity(auditStore, logger)

	// Pre-create per-agent rate limiters
	for name, agent := range agents {
		if agent.Egress != nil && agent.Egress.RateLimit > 0 {
			window := agent.Egress.RateWindow
			if window <= 0 {
				window = 60
			}
			fp.agentLimiters[name] = NewRateLimiter(agent.Egress.RateLimit, window)
		}
	}

	return fp
}

// Wrap returns a handler that dispatches CONNECT and absolute-URL requests to the
// forward proxy, while passing everything else through to the existing mux.
func (fp *ForwardProxy) Wrap(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			fp.handleConnect(w, r)
			return
		}
		if r.URL.IsAbs() && r.URL.Host != "" {
			fp.handleHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// buildForwardProxyIdentity wires the forward proxy into the same
// identity contract the gateway uses. fullCfg may be nil (legacy callers
// that constructed only ForwardProxyConfig); in that case the resolver
// runs against an empty principal store and the surface stays in
// loopback-header mode for backwards compatibility.
func buildForwardProxyIdentity(cfg *config.ForwardProxyConfig, fullCfg *config.Config) (resolve.Resolver, resolve.Config, bool) {
	var principals []resolve.ConfigPrincipal
	var deployProfile string
	var requireSurface bool
	if fullCfg != nil {
		deployProfile = fullCfg.Deployment.Profile
		requireSurface = fullCfg.Deployment.RequireSurfaceAuth
		for _, p := range fullCfg.Identity.Principals {
			toks := make([]resolve.ConfigToken, 0, len(p.Tokens))
			for _, t := range p.Tokens {
				toks = append(toks, resolve.ConfigToken{
					ID: t.ID, Type: t.Type, Hash: t.Hash,
					CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt,
				})
			}
			principals = append(principals, resolve.ConfigPrincipal{
				ID: p.ID, DisplayName: p.DisplayName, Kind: p.Kind,
				WorkspaceID: p.WorkspaceID, AllowedSurfaces: p.AllowedSurfaces,
				Tokens:  toks,
				Context: configPrincipalContextForward(p.Context),
			})
		}
	}
	store := resolve.NewMemoryTokenStoreWithClock(resolve.PrincipalsFromConfig(principals), nil)
	resolver := resolve.NewDefaultResolver(store, nil)

	policy := resolve.DerivePolicy(resolve.SurfaceAuthInput{
		Surface:                resolve.SurfaceHTTPEgress,
		Profile:                resolve.ProfileFromString(deployProfile),
		RequireSurfaceAuth:     requireSurface,
		RequireAuthOverride:    cfg.RequireAuth,
		AuthMethods:            cfg.AuthMethods,
		TrustedLoopbackHeaders: cfg.TrustedLoopbackHeaders,
		AllowedTokenTypes:      []resolve.TokenType{resolve.TokenTypeProxyBasic},
	})
	return resolver, policy.ResolverConfig, policy.RequireAuth
}

// resolveIdentity runs the identity resolver against an incoming request
// and returns the full Result. Callers use Result.Principal for policy,
// Result.ReportedActor for display/audit, and Result.RequireMinimumTrust
// to fail closed when require_auth is on. The legacy X-Oktsec-Agent
// header is consumed via Evidence.ConfigAgent (loopback header path);
// callers strip it from the request so it never reaches the upstream
// destination. Proxy-Authorization is also stripped at the call site.
func (fp *ForwardProxy) resolveIdentity(r *http.Request) resolve.Result {
	res, _ := fp.resolver.Resolve(r.Context(), fp.resolverConfig, resolve.Evidence{
		Surface:     resolve.SurfaceHTTPEgress,
		Header:      r.Header,
		RemoteAddr:  r.RemoteAddr,
		ConfigAgent: r.Header.Get("X-Oktsec-Agent"),
	})
	return res
}

// extractSession reads and strips the X-Oktsec-Session header.
func extractSession(r *http.Request) string {
	session := r.Header.Get("X-Oktsec-Session")
	r.Header.Del("X-Oktsec-Session")
	return strings.TrimSpace(session)
}

// handleConnect handles HTTPS tunneling via the CONNECT method.
func (fp *ForwardProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host
	res := fp.resolveIdentity(r)
	r.Header.Del("X-Oktsec-Agent")
	r.Header.Del("Proxy-Authorization")
	if fp.requireAuth {
		if err := res.RequireMinimumTrust(resolve.TrustAuthenticated); err != nil {
			w.Header().Set("Proxy-Authenticate", `Basic realm="oktsec forward proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}
	auth := authFromResolveResult(res)
	agent := res.Principal.ID
	if agent == "unknown" {
		agent = ""
	}
	session := extractSession(r)

	policy := fp.resolvePolicy(agent)
	if !policy.DomainAllowed(host) {
		fp.logger.Warn("forward proxy: blocked CONNECT domain", "host", host, "agent", agent, "remote", r.RemoteAddr)
		fp.logProxyEntry(fp.logAgent(agent, r.RemoteAddr), "CONNECT", host, audit.StatusBlocked, "proxy_blocked_domain", "", session, 0, start, auth)
		http.Error(w, "Forbidden: domain blocked by proxy policy", http.StatusForbidden)
		return
	}

	if !fp.allowRate(agent, r.RemoteAddr) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// SSRF: validate host before connecting
	connectHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		connectHost = h
	}
	if err := ValidateHost(connectHost); err != nil {
		fp.logger.Warn("forward proxy: SSRF blocked CONNECT", "host", host, "error", err)
		fp.logProxyEntry(r.RemoteAddr, "CONNECT", host, audit.StatusBlocked, "proxy_ssrf_blocked", "", session, 0, start, auth)
		http.Error(w, "Forbidden: SSRF protection", http.StatusForbidden)
		return
	}

	// Dial the target — chain through upstream proxy if configured
	targetConn, err := fp.dialTarget(r.Context(), host)
	if err != nil {
		fp.logger.Error("forward proxy: CONNECT dial failed", "host", host, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close() //nolint:errcheck // best-effort cleanup

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fp.logger.Error("forward proxy: hijack not supported")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fp.logger.Error("forward proxy: hijack failed", "error", err)
		return
	}
	defer clientConn.Close() //nolint:errcheck // best-effort cleanup

	// Send 200 Connection Established
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		fp.logger.Error("forward proxy: write 200 failed", "error", err)
		return
	}

	// Bidirectional copy with idle timeout
	idleTimeout := 5 * time.Minute
	done := make(chan struct{}, 2)
	var clientBytes, targetBytes int64

	go func() {
		defer func() { done <- struct{}{} }()
		clientBytes, _ = copyWithDeadline(targetConn, clientConn, idleTimeout)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		targetBytes, _ = copyWithDeadline(clientConn, targetConn, idleTimeout)
	}()

	// Wait for either direction to finish
	<-done

	fp.logProxyEntry(fp.logAgent(agent, r.RemoteAddr), "CONNECT", host, "tunneled", "proxy_allowed", "", session, clientBytes+targetBytes, start, auth)
}

// handleHTTP handles plain HTTP forward proxying with content scanning.
func (fp *ForwardProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	res := fp.resolveIdentity(r)
	r.Header.Del("X-Oktsec-Agent")
	r.Header.Del("Proxy-Authorization")
	if fp.requireAuth {
		if err := res.RequireMinimumTrust(resolve.TrustAuthenticated); err != nil {
			w.Header().Set("Proxy-Authenticate", `Basic realm="oktsec forward proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}
	auth := authFromResolveResult(res)
	agent := res.Principal.ID
	if agent == "unknown" {
		agent = ""
	}
	session := extractSession(r)
	logAgent := fp.logAgent(agent, r.RemoteAddr)

	policy := fp.resolvePolicy(agent)
	if !policy.DomainAllowed(host) {
		fp.logger.Warn("forward proxy: blocked HTTP domain", "host", host, "agent", agent, "remote", r.RemoteAddr)
		fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_blocked_domain", "", session, 0, start, auth)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "domain blocked by proxy policy"})
		return
	}

	if !fp.allowRate(agent, r.RemoteAddr) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	// SSRF: validate target host when using upstream proxy (SafeDialContext
	// handles this for direct connections, but with an upstream proxy the
	// transport dials the proxy, not the target).
	if fp.upstreamProxy {
		ssrfHost := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			ssrfHost = h
		}
		if err := ValidateHost(ssrfHost); err != nil {
			fp.logger.Warn("forward proxy: SSRF blocked HTTP", "host", host, "error", err)
			fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_ssrf_blocked", "", session, 0, start, auth)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden: SSRF protection"})
			return
		}
	}

	maxBody := fp.cfg.MaxBodySize
	if maxBody <= 0 {
		maxBody = 1 << 20 // 1 MB default
	}

	// Read request body for scanning
	var bodyBytes []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, maxBody+1)
		var err error
		bodyBytes, err = io.ReadAll(limited)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
			return
		}
		_ = r.Body.Close()
	}

	// Scan request body
	if policy.ScanRequests && len(bodyBytes) > 0 && int64(len(bodyBytes)) <= maxBody {
		outcome, err := fp.scanner.ScanContent(context.Background(), string(bodyBytes))
		if err != nil {
			fp.logger.Error("forward proxy: request scan failed", "error", err)
		} else if outcome.Verdict == engine.VerdictBlock || fp.hasCategoryBlock(outcome, policy) {
			rulesJSON := verdict.EncodeFindings(outcome.Findings)
			fp.logger.Warn("forward proxy: blocked request content",
				"host", host, "agent", agent, "remote", r.RemoteAddr, "findings", len(outcome.Findings))
			fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_blocked_content", rulesJSON, session, 0, start, auth)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "request blocked by content scan",
				"detail": fmt.Sprintf("%d security finding(s) detected", len(outcome.Findings)),
			})
			return
		}
	}

	// Build outgoing request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), strings.NewReader(string(bodyBytes)))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create proxy request"})
		return
	}

	// Copy headers (except hop-by-hop)
	copyHeaders(outReq.Header, r.Header)
	outReq.ContentLength = int64(len(bodyBytes))

	// Forward the request
	resp, err := fp.transport.RoundTrip(outReq)
	if err != nil {
		fp.logger.Error("forward proxy: upstream request failed", "host", host, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request failed"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to read upstream response"})
		return
	}

	// Scan response body if configured
	if policy.ScanResponses && len(respBody) > 0 && int64(len(respBody)) <= maxBody {
		outcome, err := fp.scanner.ScanContent(context.Background(), string(respBody))
		if err != nil {
			fp.logger.Error("forward proxy: response scan failed", "error", err)
		} else if outcome.Verdict == engine.VerdictBlock || fp.hasCategoryBlock(outcome, policy) {
			rulesJSON := verdict.EncodeFindings(outcome.Findings)
			fp.logger.Warn("forward proxy: blocked response content",
				"host", host, "agent", agent, "remote", r.RemoteAddr, "findings", len(outcome.Findings))
			fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_blocked_response", rulesJSON, session, 0, start, auth)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "response blocked by content scan",
				"detail": fmt.Sprintf("%d security finding(s) detected", len(outcome.Findings)),
			})
			return
		}
	}

	// Copy response headers and body back to client
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	fp.logProxyEntry(logAgent, r.Method, host, "forwarded", "proxy_allowed", "", session, int64(len(bodyBytes)+len(respBody)), start, auth)
}

// resolvePolicy returns the merged egress policy for an agent.
func (fp *ForwardProxy) resolvePolicy(agent string) *ResolvedEgressPolicy {
	if agent == "" {
		// No agent header — use global policy
		return &ResolvedEgressPolicy{
			AllowedDomains: fp.cfg.AllowedDomains,
			BlockedDomains: fp.cfg.BlockedDomains,
			ScanRequests:   fp.cfg.ScanRequests,
			ScanResponses:  fp.cfg.ScanResponses,
		}
	}
	return fp.egressEval.Resolve(agent)
}

// allowRate checks per-agent rate limit first, then global.
func (fp *ForwardProxy) allowRate(agent, remoteAddr string) bool {
	if agent != "" {
		if limiter, ok := fp.agentLimiters[agent]; ok {
			if !limiter.Allow(agent) {
				return false
			}
		}
	}
	return fp.rateLimiter.Allow(remoteAddr)
}

// logAgent returns the agent name for audit logging, falling back to remoteAddr.
func (fp *ForwardProxy) logAgent(agent, remoteAddr string) string {
	if agent != "" {
		return agent
	}
	return remoteAddr
}

// hasCategoryBlock checks if any finding's category is in the policy's blocked list.
func (fp *ForwardProxy) hasCategoryBlock(outcome *engine.ScanOutcome, policy *ResolvedEgressPolicy) bool {
	if len(policy.BlockedCategories) == 0 {
		return false
	}
	for _, f := range outcome.Findings {
		if policy.CategoryBlocked(f.Category) {
			return true
		}
	}
	return false
}

// proxyAuth captures the identity provenance fields the audit row and
// activity event need from the resolver. Built once per request after
// resolveIdentity and passed to every logProxyEntry call so the policy
// principal and the audit row can never drift. PrincipalID is the
// policy identity the resolver established for this request; activity
// emission attributes the egress event to it.
type proxyAuth struct {
	PrincipalID   string
	AuthMethod    string
	TrustLevel    string
	ReportedActor string
}

// authFromResolveResult lifts the resolver Result into the audit-friendly
// snapshot the logProxyEntry calls expect.
func authFromResolveResult(res resolve.Result) proxyAuth {
	return proxyAuth{
		PrincipalID:   res.Principal.ID,
		AuthMethod:    string(res.Principal.AuthMethod),
		TrustLevel:    string(res.Principal.TrustLevel),
		ReportedActor: res.ReportedActor.ID,
	}
}

// logProxyEntry writes an audit log entry for proxy traffic and emits
// the matching activity event. The auth snapshot threads identity
// provenance (auth_method, principal_trust_level, reported_actor)
// through to the audit row so downstream coverage / dashboard queries
// can attribute activity to the egress surface without heuristics.
//
// emitForwardProxyActivity runs after the audit insert so every audit
// row the forward proxy writes has a paired activity event. Activity
// emission is async with a short timeout: a slow or failing activity
// store cannot affect the request latency or the security decision.
func (fp *ForwardProxy) logProxyEntry(remoteAddr, method, host, status, policyDecision, rulesTriggered, sessionID string, bytesTransferred int64, start time.Time, auth proxyAuth) {
	entry := audit.Entry{
		ID:                  uuid.New().String(),
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		FromAgent:           remoteAddr,
		ToAgent:             host,
		ContentHash:         fmt.Sprintf("%s:%d", method, bytesTransferred),
		Status:              status,
		PolicyDecision:      policyDecision,
		RulesTriggered:      rulesTriggered,
		SessionID:           sessionID,
		LatencyMs:           time.Since(start).Milliseconds(),
		AuthMethod:          auth.AuthMethod,
		PrincipalTrustLevel: auth.TrustLevel,
		ReportedActor:       auth.ReportedActor,
	}
	fp.audit.Log(entry)
	fp.emitForwardProxyActivity(entry.ID, auth, host, method, status, policyDecision, sessionID)
}

// SetActivityStore lets callers inject a custom activityWriter (e.g., a
// recorder in tests, or a future shared store wired by a higher-level
// orchestrator). Pass nil to disable activity dual-write entirely. Safe
// to call before the proxy starts serving; not safe to swap mid-flight.
func (fp *ForwardProxy) SetActivityStore(w activityWriter) {
	fp.activity = w
}

// emitForwardProxyActivity writes one activity event correlated to the
// audit row just logged. Runs in a fresh background context with a
// bounded timeout so a slow DB cannot delay the request handler.
// Insert errors are logged at warn — they never affect the policy
// decision or the audit row.
//
// The activity event uses a fresh UUID so two audit rows from the same
// request (e.g., a CONNECT tunnel followed by a forward) do not
// collide on the activity primary key. Correlation back to the audit
// row goes through AuditEntryID.
func (fp *ForwardProxy) emitForwardProxyActivity(auditID string, auth proxyAuth, host, method, status, policyDecision, sessionID string) {
	if fp.activity == nil {
		return
	}
	ev := activity.Event{
		ID:                  uuid.New().String(),
		Timestamp:           time.Now().UTC(),
		PrincipalID:         principalIDOrUnknown(auth.PrincipalID),
		ReportedActor:       auth.ReportedActor,
		AuthMethod:          auth.AuthMethod,
		PrincipalTrustLevel: auth.TrustLevel,
		Surface:             activity.SurfaceHTTPEgressProxy,
		EventType:           activity.EventEgressRequest,
		EvidenceType:        activity.EvidenceProxy,
		SessionID:           sessionID,
		AuditEntryID:        auditID,
		Status:              status,
		PolicyDecision:      policyDecision,
		CoverageMode:        activity.CoverageFromAuthMethod(auth.AuthMethod),
		Confidence:          activity.ConfidenceFromAuthMethod(auth.AuthMethod),
		ResourceType:        "http_host",
		ResourceLabel:       host,
		ResourceID:          method + " " + host,
	}
	go func() {
		// Detached context: the request context can be cancelled by the
		// time the goroutine runs (CONNECT tunnel torn down, response
		// flushed), and activity should still land if the DB is reachable.
		ctx, cancel := context.WithTimeout(context.Background(), activityInsertTimeout)
		defer cancel()
		if err := fp.activity.Insert(ctx, ev); err != nil {
			fp.logger.Warn("activity insert failed", "error", err, "audit_id", auditID, "surface", "http_egress_proxy")
		}
	}()
}

// buildForwardProxyActivity constructs the activity store the forward
// proxy uses for dual-write. Returns nil when the audit store is nil,
// does not expose a *sql.DB, or migration fails: callers continue
// audit-only and the coverage matrix falls back to its audit-backed
// reader. Mirrors buildGatewayActivity in the gateway package; kept
// per-package to avoid an import cycle on activityWriter.
func buildForwardProxyActivity(auditStore *audit.Store, logger *slog.Logger) activityWriter {
	if auditStore == nil {
		return nil
	}
	db := auditStore.DB()
	if db == nil {
		return nil
	}
	dialect := activity.Dialect(auditStore.DialectName())
	if dialect == "" {
		logger.Warn("activity store skipped: audit store reports unknown dialect", "surface", "http_egress_proxy")
		return nil
	}
	if err := activity.Migrate(db, dialect); err != nil {
		logger.Warn("activity store skipped: migrate failed", "surface", "http_egress_proxy", "error", err)
		return nil
	}
	return activity.NewSQLStore(db, dialect)
}

// principalIDOrUnknown enforces activity.Event's PrincipalID-required
// invariant. The forward proxy can run unauthenticated in local mode,
// in which case the resolver returns an empty principal — emit
// "unknown" so the activity row still validates and can be filtered
// out by the dashboard's diagnostic-quality view.
func principalIDOrUnknown(id string) string {
	if id == "" {
		return "unknown"
	}
	return id
}

// dialTarget connects to the target host, chaining through the upstream proxy
// when one is configured (e.g., inside Docker Sandbox). Without an upstream
// proxy, it dials the target directly using the SSRF-safe dialer.
func (fp *ForwardProxy) dialTarget(ctx context.Context, host string) (net.Conn, error) {
	if !fp.upstreamProxy {
		return SafeDialContext(ctx, "tcp", host)
	}

	// Chain through upstream proxy via CONNECT
	proxyURL := upstreamProxyURL()
	if proxyURL == nil {
		return SafeDialContext(ctx, "tcp", host)
	}

	d := &net.Dialer{Timeout: 5 * time.Second}
	proxyConn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy %s: %w", proxyURL.Host, err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("CONNECT to upstream proxy: %w", err)
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("read CONNECT response from upstream proxy: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT returned %d", resp.StatusCode)
	}

	return proxyConn, nil
}

// upstreamProxyURL returns the configured upstream proxy URL, if any.
func upstreamProxyURL() *url.URL {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(key); v != "" {
			if u, err := url.Parse(v); err == nil {
				return u
			}
		}
	}
	return nil
}

// hasUpstreamProxy checks if an upstream HTTP proxy is configured via environment.
func hasUpstreamProxy() bool {
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

// copyHeaders copies HTTP headers, skipping hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	hop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	for k, vv := range src {
		if hop[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// copyWithDeadline copies from src to dst, resetting the deadline on activity.
func copyWithDeadline(dst, src net.Conn, idle time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			nw, werr := dst.Write(buf[:n])
			total += int64(nw)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			return total, err
		}
	}
}

// configPrincipalContextForward lifts the YAML PrincipalContextConfig
// into the resolver-side neutral context. Empty in, empty out. Mirrors
// the helpers in gateway and hooks; lives here to keep the resolver
// independent of internal/config.
func configPrincipalContextForward(c config.PrincipalContextConfig) resolve.ConfigPrincipalContext {
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
