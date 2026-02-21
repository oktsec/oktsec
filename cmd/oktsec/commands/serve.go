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
	"github.com/oktsec/oktsec/internal/proxy"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var port int
	var bind string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the oktsec proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				// Fall back to defaults if no config file
				cfg = config.Defaults()
			}

			if port != 0 {
				cfg.Server.Port = port
			}
			if bind != "" {
				cfg.Server.Bind = bind
			}

			if err := cfg.Validate(); err != nil {
				return err
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

			srv, err := proxy.NewServer(cfg, logger)
			if err != nil {
				return err
			}

			// Print startup banner with dashboard access code
			printBanner(cfg, srv.DashboardCode())

			// Graceful shutdown on SIGINT/SIGTERM
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() {
				errCh <- srv.Start()
			}()

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return srv.Shutdown(shutdownCtx)
			}
		},
	}

	cmd.Flags().IntVar(&port, "port", 0, "override server port")
	cmd.Flags().StringVar(&bind, "bind", "", "address to bind (default: 127.0.0.1)")
	return cmd
}

func printBanner(cfg *config.Config, dashCode string) {
	bindAddr := cfg.Server.Bind
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	mode := "observe"
	if cfg.Identity.RequireSignature {
		mode = "enforce"
	}

	fmt.Println()
	fmt.Println("  oktsec proxy")
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  API:        http://%s:%d/v1/message\n", bindAddr, cfg.Server.Port)
	fmt.Printf("  Dashboard:  http://%s:%d/dashboard\n", bindAddr, cfg.Server.Port)
	fmt.Printf("  Health:     http://%s:%d/health\n", bindAddr, cfg.Server.Port)
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Access code:  %s\n", dashCode)
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Mode: %s  |  Agents: %d\n", mode, len(cfg.Agents))
	fmt.Println()
	fmt.Println("  Enter this code in the browser to access the dashboard.")
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()
}
