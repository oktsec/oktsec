package commands

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/fatih/color"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var port int
	var bind string
	var noBrowser bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the oktsec proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startServer(cfgFile, runOpts{
				port:      port,
				bind:      bind,
				noBrowser: noBrowser,
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", 0, "override server port")
	cmd.Flags().StringVar(&bind, "bind", "", "address to bind (default: 127.0.0.1)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "don't open dashboard in browser")
	return cmd
}

func printBanner(cfg *config.Config, dashCode string) {
	cyan := color.New(color.FgCyan).SprintFunc()
	boldYellow := color.New(color.FgYellow, color.Bold).SprintFunc()

	bindAddr := cfg.Server.Bind
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	mode := color.GreenString("observe")
	if cfg.Identity.RequireSignature {
		mode = color.RedString("enforce")
	}

	fmt.Println()
	fmt.Printf("  %s\n", color.New(color.Bold).Sprint("oktsec"))
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  API:        %s\n", cyan(fmt.Sprintf("http://%s:%d/v1/message", bindAddr, cfg.Server.Port)))
	fmt.Printf("  Dashboard:  %s\n", cyan(fmt.Sprintf("http://%s:%d/dashboard", bindAddr, cfg.Server.Port)))
	fmt.Printf("  Health:     %s\n", cyan(fmt.Sprintf("http://%s:%d/health", bindAddr, cfg.Server.Port)))
	if cfg.ForwardProxy.Enabled {
		fpBind := cfg.ForwardProxy.Bind
		if fpBind == "" {
			fpBind = bindAddr
		}
		fmt.Printf("  Egress:     %s\n", cyan(fmt.Sprintf("http://%s:%d", fpBind, cfg.ForwardProxy.Port)))
	}
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Access code:  %s\n", boldYellow(dashCode))
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Mode: %s  |  Agents: %d\n", mode, len(cfg.Agents))
	if len(cfg.Agents) == 0 {
		fmt.Println("  ────────────────────────────────────────")
		fmt.Println("  No agents configured. Run 'oktsec run' to get started.")
	}
	fmt.Println()
}

// openDashboard opens the dashboard URL in the default browser.
// Skips in CI environments. Fails silently on error.
func openDashboard(cfg *config.Config) {
	if os.Getenv("CI") != "" {
		return
	}

	bindAddr := cfg.Server.Bind
	if bindAddr == "" || bindAddr == "0.0.0.0" || bindAddr == "::" {
		bindAddr = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s:%d/dashboard", bindAddr, cfg.Server.Port)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return
	}
	if err := cmd.Start(); err == nil {
		go func() { _ = cmd.Wait() }()
	}
}
