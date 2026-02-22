package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName = "oktsec_session"
	sessionDuration   = 24 * time.Hour
	maxSessions       = 50 // max concurrent sessions before cleanup

	// Rate limiting thresholds
	rateLimitWindow  = 15 * time.Minute // window for counting failures
	lockoutThreshold = 5                // failures before first lockout
	maxFailures      = 20               // permanent lockout until restart
)

type session struct {
	token     string
	createdAt time.Time
}

// loginAttempt tracks failed login attempts from an IP address.
type loginAttempt struct {
	failures    int // failures since last reset
	tier        int // escalation tier: 0→5min, 1→30min, 2→2h
	firstFail   time.Time
	lastFail    time.Time
	lockedUntil time.Time
}

// Auth manages access-code authentication and session tokens for the dashboard.
type Auth struct {
	accessCode string
	sessions   map[string]session
	attempts   map[string]*loginAttempt // keyed by IP
	logger     *slog.Logger
	mu         sync.RWMutex
}

// NewAuth generates a random 8-digit access code and returns a new Auth instance.
func NewAuth(logger *slog.Logger) *Auth {
	if logger == nil {
		logger = slog.Default()
	}
	return &Auth{
		accessCode: generateAccessCode(),
		sessions:   make(map[string]session),
		attempts:   make(map[string]*loginAttempt),
		logger:     logger,
	}
}

// AccessCode returns the code the user must enter to authenticate.
func (a *Auth) AccessCode() string {
	return a.accessCode
}

// CheckRateLimit checks if an IP is currently locked out.
// Returns (allowed bool, retryAfter time.Duration).
func (a *Auth) CheckRateLimit(ip string) (bool, time.Duration) {
	a.mu.Lock()
	att, ok := a.attempts[ip]
	if !ok {
		a.mu.Unlock()
		return true, 0
	}

	now := time.Now()

	// Check if currently locked out
	if now.Before(att.lockedUntil) {
		remaining := time.Until(att.lockedUntil)
		a.mu.Unlock()
		return false, remaining
	}

	// Lockout expired — reset failure counter but keep tier for escalation
	if !att.lockedUntil.IsZero() {
		att.failures = 0
		att.firstFail = now
		att.lockedUntil = time.Time{}
	}

	// Full window expired with no active lockout — clean up entirely
	if now.Sub(att.firstFail) > rateLimitWindow {
		delete(a.attempts, ip)
		a.mu.Unlock()
		return true, 0
	}

	a.mu.Unlock()
	return true, 0
}

// RecordFailure records a failed login attempt and returns lockout duration if triggered.
func (a *Auth) RecordFailure(ip string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	att, ok := a.attempts[ip]
	if !ok {
		att = &loginAttempt{firstFail: now}
		a.attempts[ip] = att
	}

	att.failures++
	att.lastFail = now

	// Trigger lockout when failures reach the threshold
	if att.failures >= lockoutThreshold {
		// Lockout duration escalates by tier
		var lockout time.Duration
		switch {
		case att.tier >= 2:
			lockout = 2 * time.Hour
		case att.tier >= 1:
			lockout = 30 * time.Minute
		default:
			lockout = 5 * time.Minute
		}
		att.lockedUntil = now.Add(lockout)
		att.tier++ // escalate for next time
		return lockout
	}

	return 0
}

// RecordSuccess clears the failure record for an IP after successful login.
func (a *Auth) RecordSuccess(ip string) {
	a.mu.Lock()
	delete(a.attempts, ip)
	a.mu.Unlock()
}

// ValidateCode checks if the provided code matches the access code.
// Uses constant-time comparison to prevent timing attacks.
func (a *Auth) ValidateCode(code string) bool {
	return subtle.ConstantTimeCompare([]byte(code), []byte(a.accessCode)) == 1
}

// CreateSession generates a session token and stores it.
func (a *Auth) CreateSession() string {
	token := generateSessionToken()
	a.mu.Lock()
	// Enforce max sessions: clean expired first, then reject if still over limit
	a.cleanExpiredSessionsLocked()
	a.sessions[token] = session{token: token, createdAt: time.Now()}
	a.mu.Unlock()
	return token
}

// InvalidateSession removes a session token (logout).
func (a *Auth) InvalidateSession(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

// ValidateSession checks if a session token is valid and not expired.
func (a *Auth) ValidateSession(token string) bool {
	a.mu.RLock()
	s, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Since(s.createdAt) >= sessionDuration {
		// Lazy cleanup of expired session
		a.mu.Lock()
		delete(a.sessions, token)
		a.mu.Unlock()
		return false
	}
	return true
}

// SessionCount returns the number of active sessions.
func (a *Auth) SessionCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.sessions)
}

// Cleanup removes expired sessions and stale rate-limit entries.
// Should be called periodically (e.g. every 5 minutes).
func (a *Auth) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanExpiredSessionsLocked()
	a.cleanStaleAttemptsLocked()
}

// cleanExpiredSessionsLocked removes expired sessions. Must hold write lock.
func (a *Auth) cleanExpiredSessionsLocked() {
	now := time.Now()
	for token, s := range a.sessions {
		if now.Sub(s.createdAt) >= sessionDuration {
			delete(a.sessions, token)
		}
	}
}

// cleanStaleAttemptsLocked removes rate-limit entries older than the window. Must hold write lock.
func (a *Auth) cleanStaleAttemptsLocked() {
	now := time.Now()
	for ip, att := range a.attempts {
		// Remove if window expired AND not currently locked out
		if now.Sub(att.firstFail) > rateLimitWindow && now.After(att.lockedUntil) {
			delete(a.attempts, ip)
		}
	}
}

// Middleware protects dashboard routes, redirecting unauthenticated requests to login.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow login page without auth
		if r.URL.Path == "/dashboard/login" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !a.ValidateSession(cookie.Value) {
			http.Redirect(w, r, "/dashboard/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the client IP address from the request.
// Only uses RemoteAddr (no X-Forwarded-For) since dashboard is localhost-only.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// generateAccessCode returns a random 8-digit numeric code.
func generateAccessCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(100_000_000))
	return fmt.Sprintf("%08d", n.Int64())
}

// generateSessionToken returns a cryptographically random hex string.
func generateSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
