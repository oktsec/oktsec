package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// ForwardProxy implements an HTTP forward proxy that scans traffic with Aguara.
// It handles CONNECT tunneling (HTTPS) and plain HTTP forwarding.
type ForwardProxy struct {
	cfg         *config.ForwardProxyConfig
	scanner     *engine.Scanner
	audit       *audit.Store
	rateLimiter *RateLimiter
	logger      *slog.Logger
	transport   *http.Transport
}

// NewForwardProxy creates a forward proxy with scanning and audit capabilities.
func NewForwardProxy(cfg *config.ForwardProxyConfig, scanner *engine.Scanner, auditStore *audit.Store, rateLimiter *RateLimiter, logger *slog.Logger) *ForwardProxy {
	return &ForwardProxy{
		cfg:         cfg,
		scanner:     scanner,
		audit:       auditStore,
		rateLimiter: rateLimiter,
		logger:      logger,
		transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:  5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}
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

// handleConnect handles HTTPS tunneling via the CONNECT method.
func (fp *ForwardProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host

	if !fp.domainAllowed(host) {
		fp.logger.Warn("forward proxy: blocked CONNECT domain", "host", host, "remote", r.RemoteAddr)
		fp.logProxyEntry(r.RemoteAddr, "CONNECT", host, "blocked", "proxy_blocked_domain", "", 0, start)
		http.Error(w, "Forbidden: domain blocked by proxy policy", http.StatusForbidden)
		return
	}

	if !fp.rateLimiter.Allow(r.RemoteAddr) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Dial the target
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
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

	fp.logProxyEntry(r.RemoteAddr, "CONNECT", host, "tunneled", "proxy_allowed", "", clientBytes+targetBytes, start)
}

// handleHTTP handles plain HTTP forward proxying with content scanning.
func (fp *ForwardProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	if !fp.domainAllowed(host) {
		fp.logger.Warn("forward proxy: blocked HTTP domain", "host", host, "remote", r.RemoteAddr)
		fp.logProxyEntry(r.RemoteAddr, r.Method, host, "blocked", "proxy_blocked_domain", "", 0, start)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "domain blocked by proxy policy"})
		return
	}

	if !fp.rateLimiter.Allow(r.RemoteAddr) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
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
	if fp.cfg.ScanRequests && len(bodyBytes) > 0 && int64(len(bodyBytes)) <= maxBody {
		outcome, err := fp.scanner.ScanContent(context.Background(), string(bodyBytes))
		if err != nil {
			fp.logger.Error("forward proxy: request scan failed", "error", err)
		} else if outcome.Verdict == engine.VerdictBlock {
			rulesJSON := encodeFindings(outcome.Findings)
			fp.logger.Warn("forward proxy: blocked request content",
				"host", host, "remote", r.RemoteAddr, "findings", len(outcome.Findings))
			fp.logProxyEntry(r.RemoteAddr, r.Method, host, "blocked", "proxy_blocked_content", rulesJSON, 0, start)
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
	if fp.cfg.ScanResponses && len(respBody) > 0 && int64(len(respBody)) <= maxBody {
		outcome, err := fp.scanner.ScanContent(context.Background(), string(respBody))
		if err != nil {
			fp.logger.Error("forward proxy: response scan failed", "error", err)
		} else if outcome.Verdict == engine.VerdictBlock {
			rulesJSON := encodeFindings(outcome.Findings)
			fp.logger.Warn("forward proxy: blocked response content",
				"host", host, "remote", r.RemoteAddr, "findings", len(outcome.Findings))
			fp.logProxyEntry(r.RemoteAddr, r.Method, host, "blocked", "proxy_blocked_response", rulesJSON, 0, start)
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

	fp.logProxyEntry(r.RemoteAddr, r.Method, host, "forwarded", "proxy_allowed", "", int64(len(bodyBytes)+len(respBody)), start)
}

// domainAllowed checks the host against allowed and blocked domain lists.
// BlockedDomains takes precedence. If AllowedDomains is non-empty, only those are allowed.
func (fp *ForwardProxy) domainAllowed(host string) bool {
	// Strip port for domain matching
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Blocked domains take precedence
	for _, d := range fp.cfg.BlockedDomains {
		if strings.EqualFold(hostname, d) {
			return false
		}
	}

	// If allowlist is set, only allowed domains pass
	if len(fp.cfg.AllowedDomains) > 0 {
		for _, d := range fp.cfg.AllowedDomains {
			if strings.EqualFold(hostname, d) {
				return true
			}
		}
		return false
	}

	return true
}

// logProxyEntry writes an audit log entry for proxy traffic.
func (fp *ForwardProxy) logProxyEntry(remoteAddr, method, host, status, policyDecision, rulesTriggered string, bytesTransferred int64, start time.Time) {
	entry := audit.Entry{
		ID:             uuid.New().String(),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      remoteAddr,
		ToAgent:        host,
		ContentHash:    fmt.Sprintf("%s:%d", method, bytesTransferred),
		Status:         status,
		PolicyDecision: policyDecision,
		RulesTriggered: rulesTriggered,
		LatencyMs:      time.Since(start).Milliseconds(),
	}
	fp.audit.Log(entry)
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
