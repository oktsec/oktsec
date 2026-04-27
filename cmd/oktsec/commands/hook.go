package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

// newHookCmd is the binary the Phase 2 manifest installs into Claude
// Code's settings.json. It reads one hook event from stdin, forwards
// it to the gateway's /hooks/event endpoint, and translates the
// gateway response into the per-event Claude Code response shape.
//
// Phase 2 contract (see documentation/engineering/specs/2026-04-27-
// phase2-hook-manifest-v2-spec.md section 4):
//   - PreToolUse: emit hookSpecificOutput.permissionDecision: "deny"
//     with permissionDecisionReason on a block.
//   - PostToolUse / PostToolUseFailure / PostToolBatch / Stop /
//     ConfigChange / SubagentStop: top-level decision: "block" with
//     reason and hookSpecificOutput.additionalContext.
//   - PermissionRequest: hookSpecificOutput.decision.behavior: "deny".
//   - TaskCreated / TaskCompleted: stderr + exit 2.
//   - All other events: stdout `{}`, exit 0 (observe-only).
//
// Exit code semantics follow the official Claude Code docs:
// exit 2 is blocking, exit 1 is non-blocking, exit 0 is success.
// We use exit 2 alongside the JSON shape as belt-and-suspenders.
func newHookCmd() *cobra.Command {
	var (
		port       int
		event      string
		manifestID string
	)

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Forward a Claude Code hook event to the oktsec gateway",
		Long: `Reads a Claude Code hook event from stdin, forwards it to the
oktsec gateway, and emits the response shape Claude expects for the
given event. Exits silently with code 0 if the gateway is not running
(observe mode failure-open posture; set OKTSEC_HOOK_FAIL_CLOSED=1 to
fail closed instead).

Designed for use as a Claude Code command hook installed by the
Phase 2 manifest.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If --port wasn't explicitly set, read from config so the
			// hook still works when the gateway runs on a non-default port.
			if !cmd.Flags().Changed("port") {
				cfgPath, found := config.ResolveConfigPath("", false)
				if found {
					if cfg, err := config.Load(cfgPath); err == nil && cfg.Gateway.Port > 0 {
						port = cfg.Gateway.Port
					}
				}
			}
			return runHook(port, event)
		},
	}

	cmd.Flags().IntVar(&port, "port", 9090, "gateway port")
	cmd.Flags().StringVar(&event, "event", "", "Claude Code hook event name (e.g. PreToolUse); falls back to hook_event_name in stdin payload")
	// --manifest is a marker the Phase 2 installer adds to every
	// command it writes. We accept and ignore it here so the flag
	// is invisible to Claude's parser; inventory + uninstall use the
	// presence of "--manifest v2" in the command string to know
	// which entries they own.
	cmd.Flags().StringVar(&manifestID, "manifest", "", "internal manifest version marker; do not set manually")
	_ = manifestID

	return cmd
}

func runHook(port int, eventOverride string) error {
	body, err := io.ReadAll(os.Stdin)
	if err != nil || len(body) == 0 {
		return nil // nothing to send
	}

	// Detect event family. The --event flag the installer baked into
	// the command is authoritative; falling back to hook_event_name
	// in the stdin payload covers older Claude versions that may not
	// echo the field consistently.
	event := eventOverride
	if event == "" {
		var probe struct {
			HookEventName string `json:"hook_event_name"`
		}
		if json.Unmarshal(body, &probe) == nil {
			event = probe.HookEventName
		}
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/hooks/event", port)
	client := &http.Client{Timeout: 5 * time.Second}
	req, reqErr := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if reqErr != nil {
		return nil // fail-open on construction errors (e.g. malformed URL)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Oktsec-Client", "claude-code")
	// X-Oktsec-Agent kept for backwards compatibility with the
	// pre-Phase-2 surface adapter contract; the gateway's identity
	// resolver still honors it on loopback. Drop in Phase 4.
	req.Header.Set("X-Oktsec-Agent", "claude-code")

	// Forward session_id from the payload so the gateway can group
	// events into runtime sessions (Phase 3).
	var sessionProbe struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(body, &sessionProbe) == nil && sessionProbe.SessionID != "" {
		req.Header.Set("X-Oktsec-Session", sessionProbe.SessionID)
	}

	resp, doErr := client.Do(req)
	if doErr != nil {
		// Gateway unreachable. Record one diagnostic line so the
		// dashboard can say "hooks installed but gateway unreachable"
		// instead of silence; then honor the configured posture
		// (fail-open by default).
		writeHookDiag(event, fmt.Sprintf("gateway unreachable: %v", doErr))
		if failClosed() {
			emitFailClosed(event, "oktsec gateway unreachable")
			os.Exit(2)
		}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		Decision          string `json:"decision"`
		Reason            string `json:"reason"`
		AdditionalContext string `json:"additional_context"`
	}
	_ = json.Unmarshal(respBody, &result)

	if result.Decision != "block" {
		// Allow path: explicit allow shape so tests can pin the
		// envelope. Claude tolerates an empty stdout on observed
		// events; we emit `{}` so a downstream parser never sees
		// truncation.
		fmt.Fprint(os.Stdout, "{}")
		return nil
	}

	emitBlock(event, result.Reason, result.AdditionalContext)
	os.Exit(2)
	return nil
}

// emitBlock prints the per-event Claude Code response shape on
// stdout. The Phase 2 spec section 4 enumerates every shape; this
// switch is the single place to update when Claude evolves the
// hook contract.
func emitBlock(event, reason, additionalContext string) {
	if reason == "" {
		reason = "blocked by oktsec policy"
	}
	switch event {
	case "PreToolUse":
		// PreToolUse v2.0+ shape. The deprecated top-level
		// {"decision":"block"} still works today but the spec
		// explicitly migrates us to permissionDecision.
		writeJSON(map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
		})
	case "PermissionRequest":
		writeJSON(map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName": "PermissionRequest",
				"decision": map[string]any{
					"behavior": "deny",
					"message":  reason,
				},
			},
		})
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch",
		"Stop", "ConfigChange", "SubagentStop":
		// Top-level decision: "block" with hookSpecificOutput
		// carrying additionalContext so Claude knows what the
		// blocked output was about (e.g. "rotate the credential").
		out := map[string]any{
			"decision": "block",
			"reason":   reason,
		}
		if additionalContext != "" {
			out["hookSpecificOutput"] = map[string]any{
				"hookEventName":     event,
				"additionalContext": additionalContext,
			}
		}
		writeJSON(out)
	case "TaskCreated", "TaskCompleted":
		// These events take exit-code-2 + stderr per docs; no
		// JSON shape required.
		fmt.Fprintf(os.Stderr, "oktsec: %s blocked — %s\n", event, reason)
	default:
		// Unknown / observe-only events should not normally reach
		// this branch (the gateway should not return decision:block
		// for them), but if they do we surface the reason on stderr
		// and exit 2 so policy intent is honored.
		fmt.Fprintf(os.Stderr, "oktsec: blocked — %s\n", reason)
	}
}

// emitFailClosed is the fail-closed escape hatch when the gateway
// is unreachable AND OKTSEC_HOOK_FAIL_CLOSED=1. Mirrors the block
// shape so Claude Code refuses the action.
func emitFailClosed(event, reason string) {
	emitBlock(event, reason, "")
}

func writeJSON(payload map[string]any) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(payload)
}

func failClosed() bool {
	return os.Getenv("OKTSEC_HOOK_FAIL_CLOSED") == "1"
}

// hookDiagMaxBytes caps the diagnostic file at 1 MiB. When the
// limit is exceeded we rotate by truncating; an operator running
// the doctor sees the most recent failures, not all of them.
const hookDiagMaxBytes = 1 << 20

// writeHookDiag appends a one-line JSON record to
// ~/.oktsec/hook-diag.jsonl when the gateway is unreachable. Used
// by the dashboard / doctor to say "hooks installed but gateway
// unreachable" instead of just silence. Best-effort: any error
// here is swallowed because we do not want to block the hook.
func writeHookDiag(event, message string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".oktsec")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, "hook-diag.jsonl")

	// Rotate when the file grows past the cap. Truncate is a
	// pragmatic choice: a real ring buffer would be nicer but adds
	// I/O cost on the hot path.
	if info, err := os.Stat(path); err == nil && info.Size() > hookDiagMaxBytes {
		_ = os.Truncate(path, 0)
	}

	rec := map[string]string{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"event":   event,
		"message": message,
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return
	}
	body = append(body, '\n')
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Write(body)
}

// EmitHeartbeat is the synthetic event the doctor's --emit-heartbeat
// flag posts to verify gateway round-trip. Exposed so the doctor
// can call it without re-implementing the request plumbing. Returns
// the event id the doctor displays alongside the latency measurement.
func EmitHeartbeat(port int) (string, time.Duration, error) {
	id := fmt.Sprintf("heartbeat-%s", time.Now().UTC().Format("20060102T150405.000Z"))
	id = strings.ReplaceAll(id, ":", "")
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "SessionStart",
		"session_id":      id,
		"source":          "oktsec-doctor",
		"cwd":             "doctor-heartbeat",
	})
	if err != nil {
		return "", 0, err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/hooks/event", port)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Oktsec-Client", "claude-code")
	req.Header.Set("X-Oktsec-Agent", "claude-code")
	req.Header.Set("X-Oktsec-Session", id)

	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return id, time.Since(start), fmt.Errorf("posting heartbeat: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return id, time.Since(start), fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
	}
	return id, time.Since(start), nil
}
