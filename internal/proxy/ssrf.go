package proxy

import (
	"context"
	"net"

	"github.com/oktsec/oktsec/internal/netutil"
)

// isBlockedIP delegates to netutil.IsBlockedIP.
func isBlockedIP(ip net.IP) bool {
	return netutil.IsBlockedIP(ip)
}

// looksLikeAlternativeIP delegates to netutil.LooksLikeAlternativeIP.
func looksLikeAlternativeIP(host string) bool {
	return netutil.LooksLikeAlternativeIP(host)
}

// ValidateHost delegates to netutil.ValidateHost.
func ValidateHost(host string) error {
	return netutil.ValidateHost(host)
}

// SafeDialContext delegates to netutil.SafeDialContext.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return netutil.SafeDialContext(ctx, network, addr)
}
