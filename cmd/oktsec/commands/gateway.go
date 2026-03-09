package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/gateway"
	"github.com/oktsec/oktsec/internal/llm"
	"github.com/spf13/cobra"
)

func newGatewayCmd() *cobra.Command {
	var port int
	var bind string

	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Start the MCP security gateway",
		Long:  "Start oktsec as a Streamable HTTP MCP server that fronts backend MCP servers, intercepting every tools/call with the security pipeline.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// The gateway command implies gateway enabled
			cfg.Gateway.Enabled = true

			if port != 0 {
				cfg.Gateway.Port = port
			}
			if bind != "" {
				cfg.Gateway.Bind = bind
			}

			if err := cfg.Validate(); err != nil {
				return err
			}
			if len(cfg.MCPServers) == 0 {
				return fmt.Errorf("gateway requires at least one entry in mcp_servers")
			}

			level := slog.LevelInfo
			switch cfg.Server.LogLevel {
			case "debug":
				level = slog.LevelDebug
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			gw, err := gateway.NewGateway(cfg, logger)
			if err != nil {
				return err
			}

			// Wire LLM analysis queue (async, optional)
			var llmQueue *llm.Queue
			if cfg.LLM.Enabled {
				llmQueue = setupGatewayLLM(cfg, gw, logger)
			}

			printGatewayBanner(cfg)

			// Graceful shutdown on SIGINT/SIGTERM
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// Start LLM queue before serving
			if llmQueue != nil {
				llmQueue.Start(ctx)
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- gw.Start(ctx)
			}()

			select {
			case err := <-errCh:
				if llmQueue != nil {
					llmQueue.Stop()
				}
				return err
			case <-ctx.Done():
				if llmQueue != nil {
					llmQueue.Stop()
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return gw.Shutdown(shutdownCtx)
			}
		},
	}

	cmd.Flags().IntVar(&port, "port", 0, "override gateway port")
	cmd.Flags().StringVar(&bind, "bind", "", "address to bind (default: 127.0.0.1)")
	return cmd
}

// setupGatewayLLM creates and wires the LLM analysis queue for the gateway.
// Returns the queue so the caller can start/stop it.
func setupGatewayLLM(cfg *config.Config, gw *gateway.Gateway, logger *slog.Logger) *llm.Queue {
	llmCfg := llm.Config{
		Enabled:          true,
		Provider:         llm.Provider(cfg.LLM.Provider),
		Model:            cfg.LLM.Model,
		BaseURL:          cfg.LLM.BaseURL,
		APIKeyEnv:        cfg.LLM.APIKeyEnv,
		APIVersion:       cfg.LLM.APIVersion,
		MaxTokens:        cfg.LLM.MaxTokens,
		Temperature:      cfg.LLM.Temperature,
		MaxConcurrent:    cfg.LLM.MaxConcurrent,
		QueueSize:        cfg.LLM.QueueSize,
		MaxDailyReqs:     cfg.LLM.MaxDailyReqs,
		Timeout:          cfg.LLM.Timeout,
		Analyze:          llm.AnalyzeConfig(cfg.LLM.Analyze),
		MinContentLength: cfg.LLM.MinContentLength,
		Webhook:          llm.WebhookConfig(cfg.LLM.Webhook),
	}

	// Build fallback config if configured
	var fbCfg *llm.FallbackConfig
	if cfg.LLM.Fallback.Provider != "" {
		fbCfg = &llm.FallbackConfig{
			Provider:   llm.Provider(cfg.LLM.Fallback.Provider),
			Model:      cfg.LLM.Fallback.Model,
			BaseURL:    cfg.LLM.Fallback.BaseURL,
			APIKeyEnv:  cfg.LLM.Fallback.APIKeyEnv,
			APIVersion: cfg.LLM.Fallback.APIVersion,
			MaxTokens:  cfg.LLM.Fallback.MaxTokens,
			Timeout:    cfg.LLM.Fallback.Timeout,
		}
	}

	analyzer, err := llm.NewWithFallback(llmCfg, fbCfg, logger)
	if err != nil {
		logger.Error("failed to create LLM analyzer for gateway", "error", err)
		return nil
	}

	queueCfg := llm.QueueConfig{
		Workers:      cfg.LLM.MaxConcurrent,
		BufferSize:   cfg.LLM.QueueSize,
		MaxDailyReqs: cfg.LLM.MaxDailyReqs,
	}
	queue := llm.NewQueue(analyzer, queueCfg, logger)

	// Wire budget tracker
	if cfg.LLM.Budget.DailyLimitUSD > 0 || cfg.LLM.Budget.MonthlyLimitUSD > 0 {
		budgetCfg := llm.BudgetConfig{
			DailyLimitUSD:   cfg.LLM.Budget.DailyLimitUSD,
			MonthlyLimitUSD: cfg.LLM.Budget.MonthlyLimitUSD,
			WarnThreshold:   cfg.LLM.Budget.WarnThreshold,
			OnLimit:         cfg.LLM.Budget.OnLimit,
		}
		queue.SetBudget(llm.NewBudgetTracker(budgetCfg, logger))
		logger.Info("gateway llm budget control enabled",
			"daily_limit", budgetCfg.DailyLimitUSD,
			"monthly_limit", budgetCfg.MonthlyLimitUSD,
		)
	}

	// Store LLM results in audit database
	auditStore := gw.AuditStore()
	queue.OnResult(func(result llm.AnalysisResult) {
		threatsJSON, _ := json.Marshal(result.Threats)
		intentJSON, _ := json.Marshal(result.IntentAnalysis)
		_ = auditStore.LogLLMAnalysis(audit.LLMAnalysis{
			ID:                fmt.Sprintf("llm-%s", result.MessageID),
			MessageID:         result.MessageID,
			Timestamp:         time.Now().UTC().Format(time.RFC3339),
			FromAgent:         result.FromAgent,
			ToAgent:           result.ToAgent,
			Provider:          result.ProviderName,
			Model:             result.Model,
			RiskScore:         result.RiskScore,
			RecommendedAction: result.RecommendedAction,
			Confidence:        result.Confidence,
			ThreatsJSON:       string(threatsJSON),
			IntentJSON:        string(intentJSON),
			LatencyMs:         result.LatencyMs,
			TokensUsed:        result.TokensUsed,
		})
	})

	gw.SetLLMQueue(queue)

	// Wire signal detector (triage pre-filter)
	triageCfg := cfg.LLM.Triage
	if triageCfg.Enabled {
		sd := llm.NewSignalDetector(llm.TriageConfig{
			Enabled:           true,
			SkipVerdicts:      triageCfg.SkipVerdicts,
			SensitiveKeywords: triageCfg.SensitiveKeywords,
			MinContentLength:  triageCfg.MinContentLength,
			NewAgentPairs:     triageCfg.NewAgentPairs,
			SampleRate:        triageCfg.SampleRate,
			ExternalURLs:      triageCfg.ExternalURLs,
		})
		gw.SetSignalDetector(sd)
		logger.Info("gateway llm triage enabled", "sample_rate", triageCfg.SampleRate)
	}

	logger.Info("gateway llm analysis enabled",
		"provider", cfg.LLM.Provider,
		"model", cfg.LLM.Model,
	)
	return queue
}

func printGatewayBanner(cfg *config.Config) {
	bindAddr := cfg.Gateway.Bind
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	fmt.Println()
	fmt.Println("  oktsec gateway")
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  MCP endpoint:  http://%s:%d%s\n", bindAddr, cfg.Gateway.Port, cfg.Gateway.EndpointPath)
	fmt.Printf("  Health:        http://%s:%d/health\n", bindAddr, cfg.Gateway.Port)
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Backends: %d", len(cfg.MCPServers))
	for name, srv := range cfg.MCPServers {
		fmt.Printf("  |  %s (%s)", name, srv.Transport)
	}
	fmt.Println()
	if cfg.Gateway.ScanResponses {
		fmt.Println("  Response scanning: enabled")
	}
	if cfg.LLM.Enabled {
		fmt.Printf("  LLM analysis: %s/%s\n", cfg.LLM.Provider, cfg.LLM.Model)
	}
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()
}
