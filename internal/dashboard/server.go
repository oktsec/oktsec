package dashboard

import (
	"log/slog"
	"net/http"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

// Server serves the oktsec dashboard UI.
type Server struct {
	auth   *Auth
	audit  *audit.Store
	cfg    *config.Config
	logger *slog.Logger
	mux    *http.ServeMux
}

// NewServer creates a dashboard server with access-code authentication.
func NewServer(cfg *config.Config, auditStore *audit.Store, logger *slog.Logger) *Server {
	s := &Server{
		auth:   NewAuth(),
		audit:  auditStore,
		cfg:    cfg,
		logger: logger,
		mux:    http.NewServeMux(),
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
	s.mux.HandleFunc("GET /dashboard/rules", s.handleRules)

	// HTMX partial endpoints
	s.mux.HandleFunc("GET /dashboard/api/stats", s.handleAPIStats)
	s.mux.HandleFunc("GET /dashboard/api/recent", s.handleAPIRecent)
}
