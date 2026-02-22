package dashboard

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
)

// Server serves the oktsec dashboard UI.
type Server struct {
	auth    *Auth
	audit   *audit.Store
	cfg     *config.Config
	cfgPath string
	keys    *identity.KeyStore
	scanner *engine.Scanner
	logger  *slog.Logger
	mux     *http.ServeMux
}

// NewServer creates a dashboard server with access-code authentication.
func NewServer(cfg *config.Config, cfgPath string, auditStore *audit.Store, keys *identity.KeyStore, scanner *engine.Scanner, logger *slog.Logger) *Server {
	s := &Server{
		auth:    NewAuth(logger),
		audit:   auditStore,
		cfg:     cfg,
		cfgPath: cfgPath,
		keys:    keys,
		scanner: scanner,
		logger:  logger,
		mux:     http.NewServeMux(),
	}
	s.routes()

	// Periodic cleanup of expired sessions and stale rate-limit entries
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.auth.Cleanup()
		}
	}()

	return s
}

// AccessCode returns the one-time access code displayed in the terminal.
func (s *Server) AccessCode() string {
	return s.auth.AccessCode()
}

// Handler returns the dashboard HTTP handler with auth middleware applied.
func (s *Server) Handler() http.Handler {
	return s.auth.Middleware(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /dashboard/login", s.handleLoginPage)
	s.mux.HandleFunc("POST /dashboard/login", s.handleLoginSubmit)
	s.mux.HandleFunc("POST /dashboard/logout", s.handleLogout)
	s.mux.HandleFunc("GET /dashboard", s.handleOverview)
	s.mux.HandleFunc("GET /dashboard/events", s.handleEvents)
	s.mux.HandleFunc("GET /dashboard/settings", s.handleSettings)
	s.mux.HandleFunc("GET /dashboard/agents", s.handleAgents)

	// Legacy URL redirects
	s.mux.HandleFunc("GET /dashboard/logs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/events", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /dashboard/quarantine", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/events?tab=quarantine", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /dashboard/analytics", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /dashboard/identity", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/settings", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /dashboard/agents/{name}", s.handleAgentDetail)
	s.mux.HandleFunc("GET /dashboard/rules", s.handleRules)
	s.mux.HandleFunc("GET /dashboard/rules/{category}", s.handleCategoryRules)
	s.mux.HandleFunc("POST /dashboard/identity/revoke", s.handleIdentityRevoke)
	s.mux.HandleFunc("POST /dashboard/mode/toggle", s.handleModeToggle)

	// HTMX partial endpoints
	s.mux.HandleFunc("GET /dashboard/api/stats", s.handleAPIStats)
	s.mux.HandleFunc("GET /dashboard/api/recent", s.handleAPIRecent)

	// SSE
	s.mux.HandleFunc("GET /dashboard/api/events", s.handleSSE)

	// Search
	s.mux.HandleFunc("GET /dashboard/api/search", s.handleSearch)

	// Event detail panel
	s.mux.HandleFunc("GET /dashboard/api/event/{id}", s.handleEventDetail)

	// Rule detail panel
	s.mux.HandleFunc("GET /dashboard/api/rule/{id}", s.handleRuleDetail)

	// Enforcement overrides
	s.mux.HandleFunc("GET /dashboard/rules/enforcement", s.handleEnforcementOverrides)
	s.mux.HandleFunc("POST /dashboard/rules/enforcement", s.handleSaveEnforcement)
	s.mux.HandleFunc("DELETE /dashboard/rules/enforcement/{id}", s.handleDeleteEnforcement)

	// Custom rules
	s.mux.HandleFunc("GET /dashboard/rules/custom", s.handleCustomRules)
	s.mux.HandleFunc("POST /dashboard/rules/custom", s.handleCreateCustomRule)
	s.mux.HandleFunc("DELETE /dashboard/rules/custom/{id}", s.handleDeleteCustomRule)

	// Quarantine queue API
	s.mux.HandleFunc("GET /dashboard/api/quarantine/{id}", s.handleQuarantineDetail)
	s.mux.HandleFunc("POST /dashboard/api/quarantine/{id}/approve", s.handleQuarantineApprove)
	s.mux.HandleFunc("POST /dashboard/api/quarantine/{id}/reject", s.handleQuarantineReject)

	// Agent CRUD
	s.mux.HandleFunc("POST /dashboard/agents", s.handleCreateAgent)
	s.mux.HandleFunc("POST /dashboard/agents/{name}/edit", s.handleEditAgent)
	s.mux.HandleFunc("DELETE /dashboard/agents/{name}", s.handleDeleteAgent)
	s.mux.HandleFunc("POST /dashboard/agents/{name}/keygen", s.handleAgentKeygen)

	// Rule toggles (inline enable/disable)
	s.mux.HandleFunc("POST /dashboard/api/rule/{id}/toggle", s.handleToggleRule)
	s.mux.HandleFunc("POST /dashboard/api/category/{name}/toggle", s.handleToggleCategory)
}
