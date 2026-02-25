package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	cfg           *config.Config
	cfgPath       string
	srv           *http.Server
	ln            net.Listener
	keys          *identity.KeyStore
	scanner       *engine.Scanner
	audit         *audit.Store
	dashboard     *dashboard.Server
	logger        *slog.Logger
	anomalyCancel context.CancelFunc
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
	// Root splash page
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = dashboard.SplashTmpl.Execute(w, nil)
	})

	// Mount dashboard (auth middleware applied internally)
	mux.Handle("/dashboard/", dash.Handler())
	mux.Handle("/dashboard", dash.Handler())

	// Apply middleware to the mux (API + dashboard)
	var h http.Handler = mux
	h = securityHeaders(h)
	h = logging(logger)(h)
	h = recovery(logger)(h)
	h = requestID(h)

	// Apply forward proxy wrapper OUTSIDE middleware so CONNECT requests
	// get the raw ResponseWriter (needed for Hijack). Middleware only
	// applies to API/dashboard requests that pass through to the mux.
	if cfg.ForwardProxy.Enabled {
		fp := NewForwardProxy(&cfg.ForwardProxy, scanner, auditStore,
			NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS), logger)
		h = fp.Wrap(h)
		logger.Info("forward proxy enabled",
			"blocked_domains", len(cfg.ForwardProxy.BlockedDomains),
			"allowed_domains", len(cfg.ForwardProxy.AllowedDomains),
			"scan_requests", cfg.ForwardProxy.ScanRequests,
		)
	}

	// Bind to 127.0.0.1 by default (localhost only).
	// Use server.bind config or --bind flag to change.
	bind := cfg.Server.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}

	// Try configured port, auto-find next available if busy.
	ln, actualPort, err := listenAutoPort(bind, cfg.Server.Port, logger)
	if err != nil {
		return nil, fmt.Errorf("binding port: %w", err)
	}
	cfg.Server.Port = actualPort

	srv := &http.Server{
		Handler:        h,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}
	// Set read/write timeouts only when the forward proxy is disabled.
	// CONNECT tunnels are long-lived; global timeouts would kill them.
	// The forward proxy manages its own idle timeout via copyWithDeadline.
	if !cfg.ForwardProxy.Enabled {
		srv.ReadTimeout = 15 * time.Second
		srv.WriteTimeout = 30 * time.Second
	}

	return &Server{
		cfg:       cfg,
		cfgPath:   cfgPath,
		srv:       srv,
		ln:        ln,
		keys:      keys,
		scanner:   scanner,
		audit:     auditStore,
		dashboard: dash,
		logger:    logger,
	}, nil
}

// listenAutoPort tries the configured port; if busy, scans up to 10 higher ports.
func listenAutoPort(bind string, port int, logger *slog.Logger) (net.Listener, int, error) {
	addr := fmt.Sprintf("%s:%d", bind, port)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		// When port is 0, the OS assigns a random port — return the actual port.
		actual := ln.Addr().(*net.TCPAddr).Port
		return ln, actual, nil
	}

	// Check if the error is "address already in use"
	if !errors.Is(err, syscall.EADDRINUSE) && !isAddrInUse(err) {
		return nil, 0, err
	}

	logger.Warn("port in use, searching for available port", "port", port)
	for offset := 1; offset <= 10; offset++ {
		tryPort := port + offset
		addr = fmt.Sprintf("%s:%d", bind, tryPort)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			logger.Info("using alternative port", "original", port, "actual", tryPort)
			return ln, tryPort, nil
		}
	}
	return nil, 0, fmt.Errorf("port %d and next 10 ports are all in use", port)
}

func isAddrInUse(err error) bool {
	// Portable check: look for "address already in use" in error string
	return err != nil && (errors.Is(err, syscall.EADDRINUSE) ||
		fmt.Sprintf("%v", err) == "address already in use" ||
		// net.OpError wraps the syscall error
		func() bool {
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				return errors.Is(opErr.Err, syscall.EADDRINUSE)
			}
			return false
		}())
}

// AuditStore returns the audit store for CLI queries.
func (s *Server) AuditStore() *audit.Store {
	return s.audit
}

// DashboardCode returns the one-time access code for the dashboard.
func (s *Server) DashboardCode() string {
	return s.dashboard.AccessCode()
}

// Port returns the actual port the server is bound to.
func (s *Server) Port() int {
	return s.cfg.Server.Port
}

// anomalyLoop periodically checks agent risk scores and fires alerts or suspends agents.
func (s *Server) anomalyLoop(ctx context.Context) {
	interval := s.cfg.Anomaly.CheckIntervalS
	if interval <= 0 {
		interval = 60
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkAnomalies()
		}
	}
}

func (s *Server) checkAnomalies() {
	if s.cfg.Anomaly.RiskThreshold <= 0 {
		return
	}

	risks, err := s.audit.QueryAgentRisk()
	if err != nil {
		s.logger.Error("anomaly check failed", "error", err)
		return
	}

	minMsgs := s.cfg.Anomaly.MinMessages
	if minMsgs <= 0 {
		minMsgs = 5
	}

	webhooks := NewWebhookNotifier(s.cfg.Webhooks, s.logger)

	for _, ar := range risks {
		if ar.Total < minMsgs || ar.RiskScore <= s.cfg.Anomaly.RiskThreshold {
			continue
		}

		s.logger.Warn("agent risk elevated",
			"agent", ar.Agent,
			"risk_score", ar.RiskScore,
			"total", ar.Total,
			"blocked", ar.Blocked,
		)

		webhooks.Notify(WebhookEvent{
			Event:     "agent_risk_elevated",
			From:      ar.Agent,
			Severity:  "high",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})

		if s.cfg.Anomaly.AutoSuspend {
			if agent, ok := s.cfg.Agents[ar.Agent]; ok && !agent.Suspended {
				agent.Suspended = true
				s.cfg.Agents[ar.Agent] = agent
				s.logger.Warn("agent auto-suspended", "agent", ar.Agent, "risk_score", ar.RiskScore)

				if s.cfgPath != "" {
					if err := s.cfg.Save(s.cfgPath); err != nil {
						s.logger.Error("failed to save config after auto-suspend", "error", err)
					}
				}
			}
		}
	}
}

// Start begins listening. Blocks until the server is shut down.
func (s *Server) Start() error {
	s.logger.Info("oktsec proxy starting",
		"addr", s.ln.Addr().String(),
		"require_signature", s.cfg.Identity.RequireSignature,
		"forward_proxy", s.cfg.ForwardProxy.Enabled,
	)

	// Start anomaly detection loop if configured
	if s.cfg.Anomaly.RiskThreshold > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		s.anomalyCancel = cancel
		go s.anomalyLoop(ctx)
	}

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

	return s.srv.Serve(s.ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down")
	if s.anomalyCancel != nil {
		s.anomalyCancel()
	}
	err := s.srv.Shutdown(ctx)
	s.scanner.Close()
	if cerr := s.audit.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}
