package dashboard

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName = "oktsec_session"
	sessionDuration   = 24 * time.Hour
)

type session struct {
	token     string
	createdAt time.Time
}

// Auth manages access-code authentication and session tokens for the dashboard.
type Auth struct {
	accessCode string
	sessions   map[string]session
	mu         sync.RWMutex
}

// NewAuth generates a random 8-digit access code and returns a new Auth instance.
func NewAuth() *Auth {
	return &Auth{
		accessCode: generateAccessCode(),
		sessions:   make(map[string]session),
	}
}

// AccessCode returns the code the user must enter to authenticate.
func (a *Auth) AccessCode() string {
	return a.accessCode
}

// ValidateCode checks if the provided code matches the access code.
func (a *Auth) ValidateCode(code string) bool {
	return code == a.accessCode
}

// CreateSession generates a session token and stores it.
func (a *Auth) CreateSession() string {
	token := generateSessionToken()
	a.mu.Lock()
	a.sessions[token] = session{token: token, createdAt: time.Now()}
	a.mu.Unlock()
	return token
}

// ValidateSession checks if a session token is valid and not expired.
func (a *Auth) ValidateSession(token string) bool {
	a.mu.RLock()
	s, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Since(s.createdAt) < sessionDuration
}

// Middleware protects dashboard routes, redirecting unauthenticated requests to login.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow login page and static assets without auth
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
