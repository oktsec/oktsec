package dashboard

import (
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
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

	gwMu  sync.Mutex
	gwCmd *exec.Cmd
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

	// Auto-start gateway if enabled in config and backends exist
	if cfg.Gateway.Enabled && len(cfg.MCPServers) > 0 {
		s.gwMu.Lock()
		s.startGateway()
		s.gwMu.Unlock()
	}

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

// startGateway spawns `oktsec gateway` as a child process. Caller must hold gwMu.
func (s *Server) startGateway() {
	if s.gwCmd != nil && s.gwCmd.Process != nil {
		return // already running
	}
	exe, err := os.Executable()
	if err != nil {
		s.logger.Error("failed to find executable for gateway", "error", err)
		return
	}
	args := []string{"gateway"}
	if s.cfgPath != "" {
		args = append(args, "--config", s.cfgPath)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		s.logger.Error("failed to start gateway process", "error", err)
		return
	}
	s.gwCmd = cmd
	s.logger.Info("gateway process started", "pid", cmd.Process.Pid)

	// Reap the process in the background so we detect when it exits
	go func() {
		_ = cmd.Wait()
		s.gwMu.Lock()
		if s.gwCmd == cmd {
			s.gwCmd = nil
		}
		s.gwMu.Unlock()
		s.logger.Info("gateway process exited")
	}()
}

// stopGateway stops the gateway child process. Caller must hold gwMu.
func (s *Server) stopGateway() {
	if s.gwCmd == nil || s.gwCmd.Process == nil {
		s.gwCmd = nil
		return
	}
	if err := s.gwCmd.Process.Signal(os.Interrupt); err != nil {
		s.logger.Warn("failed to send interrupt to gateway, killing", "error", err)
		_ = s.gwCmd.Process.Kill()
	}
	s.gwCmd = nil
	s.logger.Info("gateway process stopped")
}

// GatewayRunning returns true if the gateway child process is alive.
func (s *Server) GatewayRunning() bool {
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	return s.gwCmd != nil && s.gwCmd.Process != nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /dashboard/login", s.handleLoginPage)
	s.mux.HandleFunc("POST /dashboard/login", s.handleLoginSubmit)
	s.mux.HandleFunc("POST /dashboard/logout", s.handleLogout)
	s.mux.HandleFunc("GET /dashboard", s.handleOverview)
	s.mux.HandleFunc("GET /dashboard/events", s.handleEvents)
	s.mux.HandleFunc("GET /dashboard/settings", s.handleSettings)
	s.mux.HandleFunc("GET /dashboard/agents", s.handleAgents)

	s.mux.HandleFunc("GET /dashboard/graph", s.handleGraph)
	s.mux.HandleFunc("GET /dashboard/api/graph", s.handleAPIGraph)
	s.mux.HandleFunc("GET /dashboard/api/graph/edge", s.handleEdgeDetail)

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
	s.mux.HandleFunc("GET /dashboard/agents/{name...}", s.handleAgentDetail)
	s.mux.HandleFunc("GET /dashboard/audit", s.handleAudit)
	s.mux.HandleFunc("GET /dashboard/audit/sandbox", s.handleAuditSandbox)
	s.mux.HandleFunc("GET /dashboard/rules", s.handleRules)
	s.mux.HandleFunc("GET /dashboard/rules/{category}", s.handleCategoryRules)
	s.mux.HandleFunc("POST /dashboard/identity/revoke", s.handleIdentityRevoke)
	s.mux.HandleFunc("POST /dashboard/mode/toggle", s.handleModeToggle)

	// HTMX partial endpoints
	s.mux.HandleFunc("GET /dashboard/api/stats", s.handleAPIStats)
	s.mux.HandleFunc("GET /dashboard/api/recent", s.handleAPIRecent)

	// Export
	s.mux.HandleFunc("GET /dashboard/api/export/csv", s.handleExportCSV)
	s.mux.HandleFunc("GET /dashboard/api/export/json", s.handleExportJSON)

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
	s.mux.HandleFunc("POST /dashboard/agents/{name}/suspend", s.handleSuspendToggle)

	// Rule toggles (inline enable/disable)
	s.mux.HandleFunc("POST /dashboard/api/rule/{id}/toggle", s.handleToggleRule)
	s.mux.HandleFunc("POST /dashboard/api/category/{name}/toggle", s.handleToggleCategory)
	s.mux.HandleFunc("POST /dashboard/api/rules/bulk-toggle", s.handleBulkToggleRules)

	// Settings sections
	s.mux.HandleFunc("POST /dashboard/settings/default-policy", s.handleSaveDefaultPolicy)
	s.mux.HandleFunc("POST /dashboard/settings/rate-limit", s.handleSaveRateLimit)
	s.mux.HandleFunc("POST /dashboard/settings/anomaly", s.handleSaveAnomaly)
	s.mux.HandleFunc("POST /dashboard/settings/forward-proxy", s.handleSaveForwardProxy)
	s.mux.HandleFunc("POST /dashboard/settings/quarantine", s.handleSaveQuarantine)

	// Webhook channels
	s.mux.HandleFunc("POST /dashboard/settings/webhooks", s.handleSaveWebhookChannel)
	s.mux.HandleFunc("DELETE /dashboard/settings/webhooks/{name}", s.handleDeleteWebhookChannel)

	// Gateway management
	s.mux.HandleFunc("GET /dashboard/gateway", s.handleGateway)
	s.mux.HandleFunc("POST /dashboard/gateway/settings", s.handleSaveGatewaySettings)
	s.mux.HandleFunc("POST /dashboard/gateway/servers", s.handleCreateMCPServer)
	s.mux.HandleFunc("GET /dashboard/gateway/servers/{name}", s.handleMCPServerDetail)
	s.mux.HandleFunc("POST /dashboard/gateway/servers/{name}/edit", s.handleEditMCPServer)
	s.mux.HandleFunc("DELETE /dashboard/gateway/servers/{name}", s.handleDeleteMCPServer)
	s.mux.HandleFunc("GET /dashboard/api/gateway/health", s.handleGatewayHealthCheck)

	// Catch-all for unmatched dashboard paths (must be registered last)
	s.mux.HandleFunc("GET /dashboard/", s.handleNotFound)
}
