package proxy

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireAPIKey returns middleware that enforces API key authentication.
// It checks for the key in the Authorization header (Bearer token) or the
// X-API-Key header. If the configured key is empty, the middleware is a
// no-op (backwards compatible: no key = open access).
// Key comparison uses constant-time comparison to prevent timing attacks.
func requireAPIKey(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// No key configured -- pass through (backwards compatible).
		if apiKey == "" {
			return next
		}

		keyBytes := []byte(apiKey)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var provided string

			// Check Authorization: Bearer <key>
			if auth := r.Header.Get("Authorization"); auth != "" {
				if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
					provided = strings.TrimSpace(after)
				}
			}

			// Fall back to X-API-Key header
			if provided == "" {
				provided = r.Header.Get("X-API-Key")
			}

			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), keyBytes) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
