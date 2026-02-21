package dashboard

import (
	"log/slog"
	"net/http"

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
		auth:    NewAuth(),
		audit:   auditStore,
		cfg:     cfg,
		cfgPath: cfgPath,
		keys:    keys,
		scanner: scanner,
		logger:  logger,
		mux:     http.NewServeMux(),
	}
	s.routes()
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
	s.mux.HandleFunc("GET /dashboard", s.handleOverview)
	s.mux.HandleFunc("GET /dashboard/logs", s.handleLogs)
	s.mux.HandleFunc("GET /dashboard/agents", s.handleAgents)
	s.mux.HandleFunc("GET /dashboard/agents/{name}", s.handleAgentDetail)
	s.mux.HandleFunc("GET /dashboard/rules", s.handleRules)
	s.mux.HandleFunc("GET /dashboard/identity", s.handleIdentity)
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
}
