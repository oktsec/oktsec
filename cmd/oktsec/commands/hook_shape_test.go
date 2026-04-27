package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runHookBinary builds the oktsec binary, points it at a fake
// gateway via --port, pipes the given hook payload to stdin, and
// returns stdout/stderr/exit. Used by every per-event response
// shape test so we exercise the real binary path Claude Code would
// invoke.
func runHookBinary(t *testing.T, payload, event string, gatewayResponse map[string]any) (string, string, int) {
	t.Helper()

	// Spin up a fake gateway that records the inbound request and
	// returns the supplied response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gatewayResponse)
	}))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	bin := buildHookBinaryOnce(t)
	cmd := exec.Command(bin, "hook", "--port", iToStr(port), "--event", event, "--manifest", "v2")
	cmd.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Isolate $HOME so the hook diagnostic file lands in a tempdir
	// instead of polluting the developer's real ~/.oktsec.
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("running hook binary: %v\nstderr=%s", err, stderr.String())
		}
	}
	return stdout.String(), stderr.String(), exitCode
}

// buildHookBinaryOnce compiles the oktsec binary once per test
// process and caches the path in a tempdir that survives every
// individual test's t.Cleanup (so tests after the first one still
// find the binary). The dir is removed in cleanupHookBinary, called
// from TestMain.
var (
	hookBinaryPath string
	hookBinaryDir  string
)

func buildHookBinaryOnce(t *testing.T) string {
	t.Helper()
	if hookBinaryPath != "" {
		return hookBinaryPath
	}
	dir, err := os.MkdirTemp("", "oktsec-hook-test-*")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "oktsec")
	cmd := exec.Command("go", "build", "-o", out, "github.com/oktsec/oktsec/cmd/oktsec")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("go build: %v", err)
	}
	hookBinaryPath = out
	hookBinaryDir = dir
	return out
}

// hookBinaryDir is intentionally not registered for cleanup. The
// directory lives under os.TempDir() and is reaped by the OS on
// reboot; we trade a short-lived ~10 MB leak for a stable cached
// path that survives every individual test's t.Cleanup.
var _ = hookBinaryDir

// TestHook_PreToolUseBlock_EmitsModernShape locks in the Phase 2
// migration: a block on PreToolUse must come back as
// hookSpecificOutput.permissionDecision: "deny" with a
// permissionDecisionReason field. The deprecated top-level
// {"decision":"block"} shape must NOT appear.
func TestHook_PreToolUseBlock_EmitsModernShape(t *testing.T) {
	stdout, _, exit := runHookBinary(t,
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`,
		"PreToolUse",
		map[string]any{"decision": "block", "reason": "rule TC-005: destructive command"},
	)
	if exit != 2 {
		t.Errorf("exit = %d, want 2 (blocking exit code)", exit)
	}
	var out struct {
		Decision           string `json:"decision"`
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decode: %v\nstdout=%s", err, stdout)
	}
	if out.Decision != "" {
		t.Errorf("top-level decision should be empty for PreToolUse v2 shape; got %q", out.Decision)
	}
	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want deny", out.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "TC-005") {
		t.Errorf("permissionDecisionReason should contain rule id, got %q",
			out.HookSpecificOutput.PermissionDecisionReason)
	}
}

// TestHook_PostToolUseBlock_TopLevelWithContext locks in the
// post-action shape: top-level decision: "block" with
// hookSpecificOutput.additionalContext when provided.
func TestHook_PostToolUseBlock_TopLevelWithContext(t *testing.T) {
	stdout, _, exit := runHookBinary(t,
		`{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":"AKIA..."}`,
		"PostToolUse",
		map[string]any{
			"decision":           "block",
			"reason":             "credential leaked in tool output",
			"additional_context": "Rotate the exposed key before re-running.",
		},
	)
	if exit != 2 {
		t.Errorf("exit = %d, want 2", exit)
	}
	var out struct {
		Decision           string `json:"decision"`
		Reason             string `json:"reason"`
		HookSpecificOutput struct {
			HookEventName     string `json:"hookEventName"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decode: %v\nstdout=%s", err, stdout)
	}
	if out.Decision != "block" {
		t.Errorf("decision = %q, want block", out.Decision)
	}
	if out.HookSpecificOutput.HookEventName != "PostToolUse" {
		t.Errorf("hookEventName = %q, want PostToolUse", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.AdditionalContext == "" {
		t.Error("additionalContext should be populated when gateway returns it")
	}
}

// TestHook_AllowEmitsEnvelope confirms the no-block path returns
// `{}` instead of empty stdout. Empty stdout is legal but a
// concrete envelope makes downstream parsers easier to test.
func TestHook_AllowEmitsEnvelope(t *testing.T) {
	stdout, _, exit := runHookBinary(t,
		`{"hook_event_name":"PreToolUse","tool_name":"Read"}`,
		"PreToolUse",
		map[string]any{"decision": "allow"},
	)
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if strings.TrimSpace(stdout) != "{}" {
		t.Errorf("stdout = %q, want {}", stdout)
	}
}

// TestHook_FailOpenWhenGatewayDown confirms the default
// failure-open posture: gateway unreachable, no block emitted,
// exit 0.
func TestHook_FailOpenWhenGatewayDown(t *testing.T) {
	bin := buildHookBinaryOnce(t)
	// Use port 1 (privileged, almost certainly unreachable from
	// userspace) so the hook hits a connect error.
	cmd := exec.Command(bin, "hook", "--port", "1", "--event", "PreToolUse", "--manifest", "v2")
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("hook should fail-open (exit 0); got %v\nstderr=%s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), `"deny"`) {
		t.Errorf("fail-open should not emit deny; stdout=%s", stdout.String())
	}
}

func iToStr(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}
