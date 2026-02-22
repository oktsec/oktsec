package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/dashboard"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/policy"
)

// Server is the oktsec HTTP proxy server.
type Server struct {
	cfg       *config.Config
	cfgPath   string
	srv       *http.Server
	keys      *identity.KeyStore
	scanner   *engine.Scanner
	audit     *audit.Store
	dashboard *dashboard.Server
	logger    *slog.Logger
}

// NewServer creates and wires the proxy server.
func NewServer(cfg *config.Config, cfgPath string, logger *slog.Logger) (*Server, error) {
	// Load agent public keys
	keys := identity.NewKeyStore()
	if cfg.Identity.KeysDir != "" {
		if err := keys.LoadFromDir(cfg.Identity.KeysDir); err != nil {
			if cfg.Identity.RequireSignature {
				return nil, fmt.Errorf("loading keys: %w", err)
			}
			logger.Warn("could not load keys, signatures will not be verified", "error", err)
		} else {
			logger.Info("loaded agent keys", "count", keys.Count(), "agents", keys.Names())
		}
	}

	// Policy evaluator
	pol := policy.NewEvaluator(cfg)

	// Aguara scanner
	scanner := engine.NewScanner(cfg.CustomRulesDir)

	// Audit store
	auditStore, err := audit.NewStore("oktsec.db", logger, cfg.Quarantine.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("opening audit store: %w", err)
	}

	// Webhook notifier
	webhooks := NewWebhookNotifier(cfg.Webhooks, logger)

	// Handler
	handler := NewHandler(cfg, keys, pol, scanner, auditStore, webhooks, logger)

	// Dashboard
	dash := dashboard.NewServer(cfg, cfgPath, auditStore, keys, scanner, logger)

	// Routes
	mux := http.NewServeMux()
	mux.Handle("POST /v1/message", handler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": "0.1.0",
		})
	})
	mux.HandleFunc("GET /v1/quarantine/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		item, err := auditStore.QuarantineByID(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if item == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, item)
	})
	// Mount dashboard (auth middleware applied internally)
	mux.Handle("/dashboard/", dash.Handler())
	mux.Handle("/dashboard", dash.Handler())

	// Apply middleware
	var h http.Handler = mux
	h = logging(logger)(h)
	h = recovery(logger)(h)
	h = requestID(h)

	// Bind to 127.0.0.1 by default (localhost only).
	// Use server.bind config or --bind flag to change.
	bind := cfg.Server.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", bind, cfg.Server.Port),
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		cfg:       cfg,
		cfgPath:   cfgPath,
		srv:       srv,
		keys:      keys,
		scanner:   scanner,
		audit:     auditStore,
		dashboard: dash,
		logger:    logger,
	}, nil
}

// AuditStore returns the audit store for CLI queries.
func (s *Server) AuditStore() *audit.Store {
	return s.audit
}

// DashboardCode returns the one-time access code for the dashboard.
func (s *Server) DashboardCode() string {
	return s.dashboard.AccessCode()
}

// Start begins listening. Blocks until the server is shut down.
func (s *Server) Start() error {
	s.logger.Info("oktsec proxy starting",
		"addr", s.srv.Addr,
		"require_signature", s.cfg.Identity.RequireSignature,
	)

	// SIGHUP handler for hot-reloading keys (Unix only)
	if runtime.GOOS != "windows" && s.cfg.Identity.KeysDir != "" {
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				s.logger.Info("SIGHUP received, reloading keys", "dir", s.cfg.Identity.KeysDir)
				if err := s.keys.ReloadFromDir(s.cfg.Identity.KeysDir); err != nil {
					s.logger.Error("failed to reload keys", "error", err)
				} else {
					s.logger.Info("keys reloaded", "count", s.keys.Count(), "agents", s.keys.Names())
				}
			}
		}()
	}

	return s.srv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down")
	err := s.srv.Shutdown(ctx)
	s.scanner.Close()
	if cerr := s.audit.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}
