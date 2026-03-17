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
	green := color.New(color.FgGreen).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()

	bindAddr := cfg.Server.Bind
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	mode := color.New(color.FgGreen, color.Bold).Sprint("observe")
	if cfg.Identity.RequireSignature {
		mode = color.New(color.FgRed, color.Bold).Sprint("enforce")
	}

	fmt.Println()
	fmt.Printf("  %s %s\n", bold("oktsec"), dim(version))
	fmt.Printf("  %s\n", dim("See everything your AI agents execute"))
	fmt.Println()
	fmt.Printf("  %s  %s\n", dim("Dashboard"), cyan(fmt.Sprintf("http://%s:%d/dashboard", bindAddr, cfg.Server.Port)))
	fmt.Printf("  %s       %s\n", dim("Code"), color.New(color.FgYellow, color.Bold).Sprint(dashCode))
	fmt.Printf("  %s       %s\n", dim("Mode"), mode)
	fmt.Println()
	if cfg.ForwardProxy.Enabled {
		fpBind := cfg.ForwardProxy.Bind
		if fpBind == "" {
			fpBind = bindAddr
		}
		fmt.Printf("  %s     %s\n", dim("Egress"), cyan(fmt.Sprintf("http://%s:%d", fpBind, cfg.ForwardProxy.Port)))
	}
	fmt.Printf("  %s %s\n", green("●"), dim("Pipeline ready. Agents auto-register on first activity."))
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
