package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

// blockedCIDRs is a comprehensive list of RFC special-use IP ranges that
// must never be used as webhook destinations (SSRF prevention).
// Covers: private, loopback, link-local, documentation, benchmarking,
// multicast, reserved, and IPv6 transition mechanism prefixes.
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",        // "This" network (RFC 1122)
		"10.0.0.0/8",       // Private-Use (RFC 1918)
		"100.64.0.0/10",    // Shared Address / CGN (RFC 6598)
		"127.0.0.0/8",      // Loopback (RFC 1122)
		"169.254.0.0/16",   // Link-Local (RFC 3927)
		"172.16.0.0/12",    // Private-Use (RFC 1918)
		"192.0.0.0/24",     // IETF Protocol Assignments (RFC 6890)
		"192.0.2.0/24",     // TEST-NET-1 (RFC 5737)
		"192.168.0.0/16",   // Private-Use (RFC 1918)
		"198.18.0.0/15",    // Benchmarking (RFC 2544)
		"198.51.100.0/24",  // TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",   // TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",      // Multicast (RFC 5771)
		"240.0.0.0/4",      // Reserved (RFC 1112)
		"::1/128",          // IPv6 Loopback
		"fc00::/7",         // IPv6 Unique Local (RFC 4193)
		"fe80::/10",        // IPv6 Link-Local (RFC 4291)
		"2001:db8::/32",    // IPv6 Documentation (RFC 3849)
		"2001::/32",        // Teredo (RFC 4380) — embeds IPv4
		"2002::/16",        // 6to4 (RFC 3056) — embeds IPv4
		"64:ff9b::/96",     // NAT64 (RFC 6052) — embeds IPv4
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}()

// isBlockedIP checks if an IP falls within any RFC special-use range.
func isBlockedIP(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to IPv4 so
	// that IPv4 CIDRs match correctly.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// safeDialContext resolves DNS and validates the resolved IP before connecting.
// This prevents DNS rebinding and TOCTOU attacks where a hostname resolves to
// a public IP during URL validation but to a private IP at connection time.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}

	// Reject if ANY resolved IP is in a blocked range
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return nil, fmt.Errorf("blocked: %s resolves to %s (private/reserved range)", host, ip.IP)
		}
	}

	// Connect directly to validated IP (prevents re-resolution TOCTOU)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// WebhookEvent is the payload sent to webhook endpoints.
type WebhookEvent struct {
	Event     string `json:"event"`
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Severity  string `json:"severity,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Timestamp string `json:"timestamp"`
}

// WebhookNotifier sends notifications to configured webhooks.
type WebhookNotifier struct {
	webhooks []config.Webhook
	client   *http.Client
	logger   *slog.Logger
}

// NewWebhookNotifier creates a notifier from config.
// Invalid URLs (private IPs, non-HTTPS) are logged and skipped.
func NewWebhookNotifier(webhooks []config.Webhook, logger *slog.Logger) *WebhookNotifier {
	var valid []config.Webhook
	for _, wh := range webhooks {
		if err := validateWebhookURL(wh.URL); err != nil {
			logger.Warn("skipping invalid webhook URL", "url", wh.URL, "error", err)
			continue
		}
		valid = append(valid, wh)
	}
	return &WebhookNotifier{
		webhooks: valid,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: safeDialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 2 {
					return errors.New("too many redirects")
				}
				// Validate redirect destination URL (defense-in-depth;
				// safeDialContext also validates at connection time)
				if err := validateWebhookURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect to blocked URL: %w", err)
				}
				return nil
			},
		},
		logger: logger,
	}
}

// validateWebhookURL performs pre-DNS validation on webhook URLs.
// It rejects non-HTTP schemes, alternative IP encodings, and known
// blocked IP ranges. Post-DNS validation happens in safeDialContext.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("webhook URL must use http or https")
	}
	host := u.Hostname()

	// Reject alternative numeric IP encodings (hex, octal, packed decimal)
	// that bypass standard net.ParseIP but some HTTP stacks interpret.
	if looksLikeAlternativeIP(host) {
		return errors.New("webhook URL contains alternative IP encoding")
	}

	// Check parsed IP against comprehensive CIDR blocklist
	ip := net.ParseIP(host)
	if ip != nil {
		if isBlockedIP(ip) {
			return errors.New("webhook URL points to a blocked IP range")
		}
	}
	return nil
}

// looksLikeAlternativeIP detects hex (0xA9FEA9FE), dot-separated hex
// (0x7f.0x00.0x00.0x01), octal (0177.0.0.1), and packed decimal
// (2130706433) hostnames used to bypass SSRF IP blocklists.
func looksLikeAlternativeIP(host string) bool {
	// Hex prefix: 0xA9FEA9FE
	if len(host) > 2 && (host[:2] == "0x" || host[:2] == "0X") {
		return true
	}
	// Dot-separated with hex octets or leading-zero octal octets
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		for _, p := range parts {
			if len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X") {
				return true // hex octet
			}
			if len(p) > 1 && p[0] == '0' && isAllDigits(p) {
				return true // leading-zero octal
			}
		}
	}
	// Packed decimal: pure numeric hostname (e.g. 2130706433 = 127.0.0.1)
	if isAllDigits(host) {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Notify sends the event to all matching webhooks (fire-and-forget).
func (n *WebhookNotifier) Notify(event WebhookEvent) {
	for _, wh := range n.webhooks {
		if !matchesEvent(wh.Events, event.Event) {
			continue
		}
		go n.send(wh.URL, event)
	}
}

// NotifyURL sends an event to a specific URL (fire-and-forget).
// The URL is validated before sending to prevent SSRF.
func (n *WebhookNotifier) NotifyURL(rawURL string, event WebhookEvent) {
	if err := validateWebhookURL(rawURL); err != nil {
		n.logger.Warn("skipping invalid notify URL", "url", rawURL, "error", err)
		return
	}
	go n.send(rawURL, event)
}

// NotifyTemplated sends a templated body to a URL. Tags like {{RULE}}, {{ACTION}},
// {{SEVERITY}}, {{FROM}}, {{TO}}, {{MESSAGE_ID}}, {{TIMESTAMP}} are replaced.
// If tmpl is empty, falls back to the default JSON payload.
func (n *WebhookNotifier) NotifyTemplated(rawURL, tmpl string, event WebhookEvent) {
	if err := validateWebhookURL(rawURL); err != nil {
		n.logger.Warn("skipping invalid notify URL", "url", rawURL, "error", err)
		return
	}
	if tmpl == "" {
		go n.send(rawURL, event)
		return
	}
	go n.sendRaw(rawURL, RenderTemplate(tmpl, event))
}

// RenderTemplate replaces {{TAG}} placeholders in a plain-text template,
// then wraps the result in Slack-compatible JSON: {"text":"..."}.
func RenderTemplate(tmpl string, event WebhookEvent) string {
	r := strings.NewReplacer(
		"{{RULE}}", event.Rule,
		"{{ACTION}}", event.Event,
		"{{SEVERITY}}", event.Severity,
		"{{FROM}}", event.From,
		"{{TO}}", event.To,
		"{{MESSAGE_ID}}", event.MessageID,
		"{{TIMESTAMP}}", event.Timestamp,
	)
	text := r.Replace(tmpl)
	payload, _ := json.Marshal(map[string]string{"text": text})
	return string(payload)
}

// DefaultWebhookTemplate is the plain-text default shown in the UI.
// RenderTemplate wraps it in Slack JSON automatically.
const DefaultWebhookTemplate = "Rule *{{RULE}}* triggered\n• Action: {{ACTION}}\n• Severity: {{SEVERITY}}\n• From: {{FROM}} → {{TO}}\n• Message: {{MESSAGE_ID}}"

func (n *WebhookNotifier) sendRaw(url, body string) {
	resp, err := n.client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		n.logger.Warn("webhook delivery failed", "url", url, "error", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		n.logger.Warn("webhook returned error", "url", url, "status", resp.StatusCode)
	}
}

func (n *WebhookNotifier) send(url string, event WebhookEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		n.logger.Error("webhook marshal failed", "error", err)
		return
	}

	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		n.logger.Warn("webhook delivery failed", "url", url, "error", err)
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.logger.Warn("webhook returned error", "url", url, "status", resp.StatusCode)
	}
}

func matchesEvent(configured []string, event string) bool {
	if len(configured) == 0 {
		return true // no filter = all events
	}
	for _, e := range configured {
		if e == event || "message_"+e == event {
			return true
		}
	}
	return false
}
