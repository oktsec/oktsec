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
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/verdict"
)

// ForwardProxy implements an HTTP forward proxy that scans traffic with Aguara.
// It handles CONNECT tunneling (HTTPS) and plain HTTP forwarding.
type ForwardProxy struct {
	cfg             *config.ForwardProxyConfig
	scanner         *engine.Scanner
	audit           *audit.Store
	rateLimiter     *RateLimiter
	egressEval      *EgressEvaluator
	agentLimiters   map[string]*RateLimiter
	logger          *slog.Logger
	transport       *http.Transport
	upstreamProxy   bool // true when HTTP_PROXY/HTTPS_PROXY is set
}

// NewForwardProxy creates a forward proxy with scanning and audit capabilities.
func NewForwardProxy(cfg *config.ForwardProxyConfig, scanner *engine.Scanner, auditStore *audit.Store, rateLimiter *RateLimiter, agents map[string]config.Agent, logger *slog.Logger) *ForwardProxy {
	// When an upstream proxy is configured (e.g., inside Docker Sandbox),
	// the transport dials the proxy, not the target. Use standard dialer
	// for proxy connections; SSRF checks are applied at handler level.
	upstream := hasUpstreamProxy()
	dialFn := safeDialContext
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
		egressEval:    NewEgressEvaluator(cfg, agents),
		agentLimiters: make(map[string]*RateLimiter),
		logger:        logger,
		upstreamProxy: upstream,
		transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialFn,
			TLSHandshakeTimeout:  5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}

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

// extractAgent reads and strips the X-Oktsec-Agent header.
func extractAgent(r *http.Request) string {
	agent := r.Header.Get("X-Oktsec-Agent")
	r.Header.Del("X-Oktsec-Agent")
	return strings.TrimSpace(agent)
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
	agent := extractAgent(r)
	session := extractSession(r)

	policy := fp.resolvePolicy(agent)
	if !policy.DomainAllowed(host) {
		fp.logger.Warn("forward proxy: blocked CONNECT domain", "host", host, "agent", agent, "remote", r.RemoteAddr)
		fp.logProxyEntry(fp.logAgent(agent, r.RemoteAddr), "CONNECT", host, audit.StatusBlocked, "proxy_blocked_domain", "", session, 0, start)
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
		fp.logProxyEntry(r.RemoteAddr, "CONNECT", host, audit.StatusBlocked, "proxy_ssrf_blocked", "", session, 0, start)
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

	fp.logProxyEntry(fp.logAgent(agent, r.RemoteAddr), "CONNECT", host, "tunneled", "proxy_allowed", "", session, clientBytes+targetBytes, start)
}

// handleHTTP handles plain HTTP forward proxying with content scanning.
func (fp *ForwardProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	agent := extractAgent(r)
	session := extractSession(r)
	logAgent := fp.logAgent(agent, r.RemoteAddr)

	policy := fp.resolvePolicy(agent)
	if !policy.DomainAllowed(host) {
		fp.logger.Warn("forward proxy: blocked HTTP domain", "host", host, "agent", agent, "remote", r.RemoteAddr)
		fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_blocked_domain", "", session, 0, start)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "domain blocked by proxy policy"})
		return
	}

	if !fp.allowRate(agent, r.RemoteAddr) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	// SSRF: validate target host when using upstream proxy (safeDialContext
	// handles this for direct connections, but with an upstream proxy the
	// transport dials the proxy, not the target).
	if fp.upstreamProxy {
		ssrfHost := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			ssrfHost = h
		}
		if err := ValidateHost(ssrfHost); err != nil {
			fp.logger.Warn("forward proxy: SSRF blocked HTTP", "host", host, "error", err)
			fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_ssrf_blocked", "", session, 0, start)
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
			fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_blocked_content", rulesJSON, session, 0, start)
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
			fp.logProxyEntry(logAgent, r.Method, host, audit.StatusBlocked, "proxy_blocked_response", rulesJSON, session, 0, start)
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

	fp.logProxyEntry(logAgent, r.Method, host, "forwarded", "proxy_allowed", "", session, int64(len(bodyBytes)+len(respBody)), start)
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

// logProxyEntry writes an audit log entry for proxy traffic.
func (fp *ForwardProxy) logProxyEntry(remoteAddr, method, host, status, policyDecision, rulesTriggered, sessionID string, bytesTransferred int64, start time.Time) {
	entry := audit.Entry{
		ID:             uuid.New().String(),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      remoteAddr,
		ToAgent:        host,
		ContentHash:    fmt.Sprintf("%s:%d", method, bytesTransferred),
		Status:         status,
		PolicyDecision: policyDecision,
		RulesTriggered: rulesTriggered,
		SessionID:      sessionID,
		LatencyMs:      time.Since(start).Milliseconds(),
	}
	fp.audit.Log(entry)
}

// dialTarget connects to the target host, chaining through the upstream proxy
// when one is configured (e.g., inside Docker Sandbox). Without an upstream
// proxy, it dials the target directly using the SSRF-safe dialer.
func (fp *ForwardProxy) dialTarget(ctx context.Context, host string) (net.Conn, error) {
	if !fp.upstreamProxy {
		return safeDialContext(ctx, "tcp", host)
	}

	// Chain through upstream proxy via CONNECT
	proxyURL := upstreamProxyURL()
	if proxyURL == nil {
		return safeDialContext(ctx, "tcp", host)
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
