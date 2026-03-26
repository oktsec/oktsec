package proxy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/dashboard"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/llm"
	"github.com/oktsec/oktsec/internal/netutil"
	"github.com/oktsec/oktsec/internal/policy"
)

// Version is set from the CLI at startup (via ldflags).
var Version = "dev"

// Server is the oktsec HTTP proxy server.
type Server struct {
	cfg           *config.Config
	cfgPath       string
	srv           *http.Server
	ln            net.Listener
	keys          *identity.KeyStore
	scanner       *engine.Scanner
	audit         *audit.Store
	handler       *Handler
	webhooks      *WebhookNotifier
	dashboard     *dashboard.Server
	llmQueue           *llm.Queue              // nil if LLM disabled
	escalationTracker  *llm.EscalationTracker  // nil if LLM escalation disabled
	logger             *slog.Logger
	anomalyCancel context.CancelFunc
	fwdSrv        *http.Server   // forward proxy (nil if disabled)
	fwdLn         net.Listener   // forward proxy listener
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
			logger.Debug("loaded agent keys", "count", keys.Count(), "agents", keys.Names())
		}
	}

	// Policy evaluator
	pol := policy.NewEvaluator(cfg)

	// Aguara scanner
	scanner := engine.NewScanner(cfg.CustomRulesDir)

	// Audit store
	dbDSN := cfg.DBPath
	if cfg.DBBackend == "postgres" || cfg.DBBackend == "postgresql" {
		dbDSN = cfg.DBDSN
	}
	auditStore, err := audit.Open(cfg.DBBackend, dbDSN, logger, cfg.Quarantine.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("opening audit store: %w — if another oktsec instance is running, stop it first", err)
	}

	// Proxy signing key for audit chain integrity
	if cfg.Identity.KeysDir != "" {
		proxyKP, err := identity.LoadKeypair(cfg.Identity.KeysDir, "_proxy")
		if err != nil {
			// First run: generate proxy keypair
			proxyKP, err = identity.GenerateKeypair("_proxy")
			if err != nil {
				logger.Warn("could not generate proxy keypair", "error", err)
			} else if saveErr := proxyKP.Save(cfg.Identity.KeysDir); saveErr != nil {
				logger.Warn("could not save proxy keypair", "error", saveErr)
			} else {
				logger.Info("generated proxy signing key for audit chain")
			}
		}
		if proxyKP != nil {
			auditStore.SetProxyKey(proxyKP.PrivateKey)
		}
	}

	// Webhook notifier
	webhooks := NewWebhookNotifier(cfg.Webhooks, logger)

	// Alert cooldown
	if cd := cfg.Alerting.Cooldown; cd != "" {
		if d, err := time.ParseDuration(cd); err == nil {
			webhooks.SetCooldown(d)
		}
	}

	// Persist alerts to audit store
	webhooks.OnAlert(func(event WebhookEvent, channel, status string) {
		_ = auditStore.LogAlert(audit.AlertEntry{
			ID:        fmt.Sprintf("alert-%s-%d", event.Event, time.Now().UnixNano()),
			Event:     event.Event,
			Severity:  event.Severity,
			Agent:     event.From,
			MessageID: event.MessageID,
			Detail:    event.Detail,
			Channel:   channel,
			Status:    status,
		})
	})

	// Handler
	handler := NewHandler(cfg, keys, pol, scanner, auditStore, webhooks, logger)

	// LLM analysis queue (async, optional)
	var llmQueue *llm.Queue
	var ruleGen *llm.RuleGenerator
	var escalationTracker *llm.EscalationTracker
	if cfg.LLM.Enabled {
		var sd *llm.SignalDetector
		llmQueue, sd = llm.SetupQueue(cfg.LLM, logger)
		if llmQueue != nil {
			// Wire rule generator
			if cfg.LLM.RuleGen.Enabled {
				outputDir := cfg.LLM.RuleGen.OutputDir
				if outputDir == "" {
					outputDir = "./rules/generated"
				}
				ruleGen = llm.NewRuleGenerator(outputDir, cfg.LLM.RuleGen.RequireApproval, cfg.LLM.RuleGen.MinConfidence)
				if cfg.LLM.RuleGen.AutoReload {
					ruleGen.OnGenerated(func(_ llm.GeneratedRule) {
						scanner.InvalidateCache()
					})
				}
			}

			// Wire LLM-driven escalation tracker (created before OnResult so
			// it can be referenced in the closure)
			escalationTracker = llm.SetupEscalation(cfg.LLM.Escalation, llmQueue, logger)

			llmQueue.OnResult(func(result llm.AnalysisResult) {
				// Store in audit database
				_ = llm.StoreResult(auditStore, result)

				// Generate rules from threats
				if ruleGen != nil {
					for _, threat := range result.Threats {
						if _, err := ruleGen.Generate(threat, result.Model, result.MessageID); err != nil {
							logger.Warn("rule generation failed", "error", err)
						}
					}
				}

				// Alert on LLM-detected threats
				if cfg.Alerting.LLMThreats && len(result.Threats) > 0 {
					topSev := audit.SeverityMedium
					for _, t := range result.Threats {
						if t.Severity == audit.SeverityCritical || t.Severity == audit.SeverityHigh {
							topSev = t.Severity
							break
						}
					}
					webhooks.Notify(WebhookEvent{
						Event:     audit.AlertEventLLMThreat,
						MessageID: result.MessageID,
						From:      result.FromAgent,
						To:        result.ToAgent,
						Severity:  topSev,
						Detail:    fmt.Sprintf("%d threat(s) detected, risk %.0f", len(result.Threats), result.RiskScore),
						Timestamp: time.Now().UTC().Format(time.RFC3339),
					})
				}

				// Feed escalation tracker
				if escalationTracker != nil {
					escalationTracker.HandleResult(result)
				}
			})

			handler.SetLLMQueue(llmQueue)
			handler.SetEscalationTracker(escalationTracker)
			if sd != nil {
				handler.SetSignalDetector(sd)
			}
		}
	}

	// Dashboard
	dash := dashboard.NewServer(cfg, cfgPath, auditStore, keys, scanner, logger)
	if llmQueue != nil {
		dash.SetLLMQueue(llmQueue)
	}
	if ruleGen != nil {
		dash.SetRuleGenerator(ruleGen)
	}

	// Agent CRUD API
	agentAPI := NewAgentAPI(cfg, cfgPath, keys, auditStore, logger)

	// API key auth middleware (no-op when api_key is empty)
	apiAuth := requireAPIKey(cfg.Server.APIKey)

	// Protected API mux: all /v1/* routes and /metrics require the API key.
	apiMux := http.NewServeMux()
	apiMux.Handle("POST /v1/message", handler)
	agentAPI.Register(apiMux)
	apiMux.HandleFunc("GET /v1/quarantine/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		item, err := auditStore.QuarantineByID(id)
		if err != nil {
			logger.Error("quarantine query failed", "error", err, "id", id)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if item == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, item)
	})
	// Audit chain verification endpoint
	apiMux.HandleFunc("GET /v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		entries, qErr := auditStore.QueryChainEntries(10000)
		if qErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query chain"})
			return
		}
		var proxyPub ed25519.PublicKey
		if cfg.Identity.KeysDir != "" {
			if pub, loadErr := identity.LoadPublicKey(cfg.Identity.KeysDir, "_proxy"); loadErr == nil {
				proxyPub = pub
			}
		}
		result := audit.VerifyChain(entries, proxyPub)
		writeJSON(w, http.StatusOK, result)
	})

	// Audit export with redaction levels
	apiMux.HandleFunc("GET /v1/audit/export", func(w http.ResponseWriter, r *http.Request) {
		level := audit.RedactionLevel(r.URL.Query().Get("redaction"))
		if level == "" {
			level = audit.RedactNone
		}
		entries, err := auditStore.Query(audit.QueryOpts{Limit: 1000})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
			return
		}
		redacted := audit.RedactEntries(entries, level)
		writeJSON(w, http.StatusOK, redacted)
	})

	// Prometheus metrics endpoint
	apiMux.Handle("GET /metrics", promhttp.Handler())

	// Top-level mux: unprotected routes + protected API behind auth middleware.
	mux := http.NewServeMux()

	// Health check -- always unauthenticated.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": Version,
		})
	})

	// Root splash page -- unauthenticated.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = dashboard.SplashTmpl.Execute(w, nil)
	})

	// Mount dashboard (has its own auth middleware internally).
	mux.Handle("/dashboard/", dash.Handler())
	mux.Handle("/dashboard", dash.Handler())

	// Mount protected routes under API key middleware.
	// Catch-all pattern "/" ensures /v1/* and /metrics are forwarded to apiMux.
	mux.Handle("/", apiAuth(apiMux))

	// Apply middleware to the mux (API + dashboard)
	var h http.Handler = mux
	h = securityHeaders(h)
	h = logging(logger)(h)
	h = recovery(logger)(h)
	h = requestID(h)

	// Bind to 127.0.0.1 by default (localhost only).
	// Use server.bind config or --bind flag to change.
	bind := cfg.Server.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}

	// Try configured port, auto-find next available if busy.
	ln, actualPort, err := netutil.ListenAutoPort(bind, cfg.Server.Port, logger)
	if err != nil {
		return nil, fmt.Errorf("binding port: %w", err)
	}
	cfg.Server.Port = actualPort

	srv := &http.Server{
		Handler:        h,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	s := &Server{
		cfg:               cfg,
		cfgPath:           cfgPath,
		srv:               srv,
		ln:                ln,
		keys:              keys,
		scanner:           scanner,
		audit:             auditStore,
		webhooks:          webhooks,
		handler:           handler,
		dashboard:         dash,
		llmQueue:          llmQueue,
		escalationTracker: escalationTracker,
		logger:            logger,
	}

	// Forward proxy on dedicated port (separate from dashboard/API)
	if cfg.ForwardProxy.Enabled {
		fp := NewForwardProxy(&cfg.ForwardProxy, scanner, auditStore,
			NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS), cfg.Agents, logger, &cfg.TrustBoundaries)

		fwdBind := cfg.ForwardProxy.Bind
		if fwdBind == "" {
			fwdBind = "127.0.0.1"
		}
		fwdLn, fwdPort, err := netutil.ListenAutoPort(fwdBind, cfg.ForwardProxy.Port, logger)
		if err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("binding forward proxy port: %w", err)
		}
		cfg.ForwardProxy.Port = fwdPort

		s.fwdLn = fwdLn
		s.fwdSrv = &http.Server{
			Handler:        fp.Wrap(http.NotFoundHandler()),
			IdleTimeout:    60 * time.Second,
			MaxHeaderBytes: 1 << 20,
			// No read/write timeouts: CONNECT tunnels are long-lived
		}
		logger.Info("forward proxy enabled",
			"addr", fwdLn.Addr().String(),
			"scan_requests", cfg.ForwardProxy.ScanRequests,
			"scan_responses", cfg.ForwardProxy.ScanResponses,
		)
	}

	return s, nil
}

// AuditStore returns the audit store for CLI queries.
func (s *Server) AuditStore() *audit.Store {
	return s.audit
}

// SetAuditStore replaces the audit store (used to share a single store
// between proxy and gateway so all events feed into one Hub).
func (s *Server) SetAuditStore(store *audit.Store) {
	s.audit = store
	if s.handler != nil {
		s.handler.audit = store
	}
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

	risks, err := s.audit.QueryAgentRisk("")
	if err != nil {
		s.logger.Error("anomaly check failed", "error", err)
		return
	}

	minMsgs := s.cfg.Anomaly.MinMessages
	if minMsgs <= 0 {
		minMsgs = 5
	}

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

		s.webhooks.Notify(WebhookEvent{
			Event:     audit.AlertEventAgentRisk,
			From:      ar.Agent,
			Severity:  audit.SeverityHigh,
			Detail:    fmt.Sprintf("risk score %.1f (threshold %.1f)", ar.RiskScore, s.cfg.Anomaly.RiskThreshold),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})

		if s.cfg.Anomaly.AutoSuspend {
			if agent, ok := s.cfg.Agents[ar.Agent]; ok && !agent.Suspended {
				agent.Suspended = true
				s.cfg.Agents[ar.Agent] = agent
				s.logger.Warn("agent auto-suspended", "agent", ar.Agent, "risk_score", ar.RiskScore)

				// Alert on agent suspension
				if s.cfg.Alerting.Suspensions {
					s.webhooks.Notify(WebhookEvent{
						Event:     audit.AlertEventAgentSuspended,
						From:      ar.Agent,
						Severity:  audit.SeverityCritical,
						Detail:    fmt.Sprintf("auto-suspended: risk %.1f exceeded threshold", ar.RiskScore),
						Timestamp: time.Now().UTC().Format(time.RFC3339),
					})
				}

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
	s.logger.Debug("oktsec proxy starting",
		"addr", s.ln.Addr().String(),
		"require_signature", s.cfg.Identity.RequireSignature,
		"forward_proxy", s.cfg.ForwardProxy.Enabled,
	)

	// Start LLM analysis queue if configured
	if s.llmQueue != nil {
		s.llmQueue.Start(context.Background())
	}

	// Start anomaly detection loop if configured
	if s.cfg.Anomaly.RiskThreshold > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		s.anomalyCancel = cancel
		go s.anomalyLoop(ctx)
	}

	// Start forward proxy on dedicated port
	if s.fwdSrv != nil {
		go func() {
			if err := s.fwdSrv.Serve(s.fwdLn); err != nil && err != http.ErrServerClosed {
				s.logger.Error("forward proxy error", "error", err)
			}
		}()
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
	s.logger.Debug("shutting down")
	if s.llmQueue != nil {
		s.llmQueue.Stop()
	}
	if s.escalationTracker != nil {
		s.escalationTracker.Stop()
	}
	if s.anomalyCancel != nil {
		s.anomalyCancel()
	}
	if s.fwdSrv != nil {
		_ = s.fwdSrv.Shutdown(ctx)
	}
	err := s.srv.Shutdown(ctx)
	s.handler.Close()
	s.scanner.Close()
	if cerr := s.audit.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}
