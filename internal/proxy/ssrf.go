package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// blockedCIDRs is a comprehensive list of RFC special-use IP ranges that
// must never be used as outbound destinations (SSRF prevention).
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
		"ff00::/8",         // IPv6 Multicast (RFC 4291)
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

// ValidateHost performs pre-connection validation of a host string.
// It rejects alternative IP encodings and known-blocked IP ranges.
// This is a reusable check for both webhooks and the forward proxy.
func ValidateHost(host string) error {
	if looksLikeAlternativeIP(host) {
		return errors.New("host uses alternative IP encoding")
	}
	ip := net.ParseIP(host)
	if ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("host %s is in a blocked IP range", host)
	}
	return nil
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
