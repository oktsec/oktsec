package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func newHookCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Forward a tool-call event to the oktsec gateway",
		Long: `Reads a hook event from stdin and forwards it to the oktsec gateway.
Exits silently with code 0 if the gateway is not running.
Designed for use as a Claude Code command hook.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHook(port)
		},
	}

	cmd.Flags().IntVar(&port, "port", 9090, "gateway port")
	return cmd
}

func runHook(port int) error {
	body, err := io.ReadAll(os.Stdin)
	if err != nil || len(body) == 0 {
		return nil // nothing to send
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/hooks/event", port)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil // fail silently
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Oktsec-Agent", "claude-code")
	req.Header.Set("X-Oktsec-Client", "claude-code")

	resp, err := client.Do(req)
	if err != nil {
		// Gateway not running — silently allow.
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse response to check for block decision.
	var result struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	respBody, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(respBody, &result) == nil && result.Decision == "block" {
		// Print reason to stderr so Claude Code shows it, then exit non-zero.
		fmt.Fprintf(os.Stderr, "oktsec: blocked — %s\n", result.Reason)
		os.Exit(2)
	}

	return nil
}
