package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

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
			gw.SetCfgPath(cfgFile)

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

			// SIGHUP handler for hot-reloading config
			sighup := make(chan os.Signal, 1)
			signal.Notify(sighup, syscall.SIGHUP)
			go func() {
				for range sighup {
					logger.Info("SIGHUP received, reloading config")
					newCfg := gw.ReloadConfig()
					if newCfg == nil {
						continue
					}

					// Rebuild LLM queue if config changed
					if llmQueue != nil {
						llmQueue.Stop()
					}
					llmQueue = nil
					gw.SetLLMQueue(nil)
					gw.SetSignalDetector(nil)

					if newCfg.LLM.Enabled {
						llmQueue = setupGatewayLLM(newCfg, gw, logger)
						if llmQueue != nil {
							llmQueue.Start(ctx)
						}
					}
					logger.Info("config reload complete")
				}
			}()

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
	queue, sd := llm.SetupQueue(cfg.LLM, logger)
	if queue == nil {
		return nil
	}

	// Store LLM results in audit database
	auditStore := gw.AuditStore()
	queue.OnResult(func(result llm.AnalysisResult) {
		_ = llm.StoreResult(auditStore, result)
	})

	gw.SetLLMQueue(queue)
	if sd != nil {
		gw.SetSignalDetector(sd)
	}
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
