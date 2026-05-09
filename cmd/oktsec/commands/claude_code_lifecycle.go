package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/oktsec/oktsec/internal/connectors/claudecode"
)

// claudeCodeLifecycleDeps wraps the four external effects needed to
// connect or disconnect Claude Code as an Oktsec runtime surface:
//   - is the `claude` CLI on PATH;
//   - run `claude mcp add` / `claude mcp remove` for the gateway entry;
//   - install / uninstall the Phase 2 hook manifest via the shared
//     claudecode connector package.
//
// All four are injected so the run, connect, and disconnect commands
// can drive the same lifecycle path without invoking the real CLI or
// mutating real ~/.claude state in tests.
type claudeCodeLifecycleDeps struct {
	hasClaudeCLI     func() bool
	runMCPAdd        func(ctx context.Context, port int, endpoint string) ([]byte, error)
	runMCPRemove     func(ctx context.Context) ([]byte, error)
	installHooksV2   func(ctx context.Context, opts claudecode.InstallOptions) (claudecode.InstallResult, error)
	uninstallHooksV2 func(ctx context.Context, opts claudecode.UninstallOptions) (claudecode.UninstallResult, error)
	executable       func() (string, error)
}

func defaultClaudeCodeLifecycleDeps() claudeCodeLifecycleDeps {
	return claudeCodeLifecycleDeps{
		hasClaudeCLI: hasClaudeCLI,
		runMCPAdd: func(ctx context.Context, port int, endpoint string) ([]byte, error) {
			url := fmt.Sprintf("http://127.0.0.1:%d%s", port, endpoint)
			//nolint:gosec // args are not user-controlled
			return exec.CommandContext(ctx,
				"claude", "mcp", "add",
				"--transport", "http",
				"--header", "X-Oktsec-Agent: claude-code",
				"--scope", "user",
				"oktsec-gateway", url,
			).CombinedOutput()
		},
		runMCPRemove: func(ctx context.Context) ([]byte, error) {
			//nolint:gosec // args are not user-controlled
			return exec.CommandContext(ctx, "claude", "mcp", "remove", "oktsec-gateway").CombinedOutput()
		},
		installHooksV2:   claudecode.InstallV2,
		uninstallHooksV2: claudecode.UninstallV2,
		executable:       os.Executable,
	}
}

// claudeCodeConnectMode controls how connect failures are reported.
//
//   - claudeConnectBestEffort is used by `oktsec run` first-run setup:
//     missing CLI, gateway-add failure and hook-install failure are all
//     non-fatal but surfaced as warnings.
//   - claudeConnectStrict is used by `oktsec connect claude-code`: any
//     real failure (gateway add or hook install) returns a non-nil
//     error so the operator knows the surface is not fully connected.
type claudeCodeConnectMode int

const (
	claudeConnectBestEffort claudeCodeConnectMode = iota
	claudeConnectStrict
)

type claudeCodeConnectOptions struct {
	Port          int
	Endpoint      string
	Mode          claudeCodeConnectMode
	FollowSymlink bool
	DryRun        bool
}

type claudeCodeDisconnectOptions struct {
	FollowSymlink bool
	DryRun        bool
}

// claudeCodeLifecycleResult is the structured outcome of a connect or
// disconnect attempt. The two callers use it to render human output
// and to decide whether the operation should return an error.
type claudeCodeLifecycleResult struct {
	GatewayAttempted bool
	GatewayOK        bool
	GatewayErr       error
	GatewayOutput    string

	HooksAttempted  bool
	HooksOK         bool
	HooksErr        error
	InstallResult   *claudecode.InstallResult
	UninstallResult *claudecode.UninstallResult

	Warnings []string
}

// Partial is true when exactly one side of the lifecycle (gateway or
// hooks) succeeded. Both succeeded or both failed is not partial.
func (r claudeCodeLifecycleResult) Partial() bool {
	if !r.GatewayAttempted || !r.HooksAttempted {
		return false
	}
	return r.GatewayOK != r.HooksOK
}

// Connected is true when the gateway entry and hook manifest are both
// present (either freshly installed in this call or already in place).
func (r claudeCodeLifecycleResult) Connected() bool {
	return r.GatewayAttempted && r.GatewayOK && r.HooksAttempted && r.HooksOK
}

// connectClaudeCodeRuntime registers oktsec-gateway via `claude mcp
// add` and installs the Phase 2 hook manifest via claudecode.InstallV2.
//
// In best-effort mode the function never returns a non-nil error; the
// caller inspects the result to decide what to print. In strict mode
// the function returns a non-nil error if either gateway registration
// or hook install fails for a real reason (idempotent / already-present
// outcomes still count as success).
func connectClaudeCodeRuntime(ctx context.Context, opts claudeCodeConnectOptions, deps claudeCodeLifecycleDeps) (claudeCodeLifecycleResult, error) {
	port := opts.Port
	if port <= 0 {
		port = 9090
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = "/mcp"
	}

	var result claudeCodeLifecycleResult

	if !deps.hasClaudeCLI() {
		msg := "claude CLI not found on PATH; install Claude Code or run `claude --version`"
		if opts.Mode == claudeConnectStrict {
			return result, errors.New(msg)
		}
		result.Warnings = append(result.Warnings, msg)
		return result, nil
	}

	// Gateway registration via `claude mcp add`. We always attempt it,
	// even when the binary path is unresolvable, so the operator gets
	// a clear failure mode.
	//
	// "Already present" is the repair case: the operator has run
	// `connect claude-code` again because hooks are missing or stale.
	// We treat it as idempotent success so the helper can continue
	// into InstallV2 and fix the half-connected state.
	result.GatewayAttempted = true
	out, err := deps.runMCPAdd(ctx, port, endpoint)
	result.GatewayOutput = string(out)
	switch {
	case err == nil:
		result.GatewayOK = true
	case isClaudeMCPAlreadyPresent(out, err):
		result.GatewayOK = true
		result.Warnings = append(result.Warnings, "oktsec-gateway entry was already registered (continuing to verify hooks)")
	default:
		result.GatewayErr = fmt.Errorf("claude mcp add: %w (output: %s)", err, strings.TrimSpace(string(out)))
		if opts.Mode == claudeConnectStrict {
			return result, result.GatewayErr
		}
		result.Warnings = append(result.Warnings, result.GatewayErr.Error())
	}

	// Hook manifest install via the shared V2 installer. The binary
	// path is required so the manifest commands can call back into
	// this binary.
	exe, exeErr := deps.executable()
	if exeErr != nil || exe == "" {
		hookErr := fmt.Errorf("resolving oktsec binary path: %w", exeErr)
		result.HooksAttempted = true
		result.HooksErr = hookErr
		if opts.Mode == claudeConnectStrict {
			return result, hookErr
		}
		result.Warnings = append(result.Warnings, hookErr.Error())
		return result, nil
	}

	result.HooksAttempted = true
	installRes, installErr := deps.installHooksV2(ctx, claudecode.InstallOptions{
		BinaryPath:    exe,
		GatewayPort:   port,
		FollowSymlink: opts.FollowSymlink,
		DryRun:        opts.DryRun,
	})
	result.InstallResult = &installRes
	if installErr != nil {
		result.HooksErr = installErr
		if opts.Mode == claudeConnectStrict {
			return result, installErr
		}
		result.Warnings = append(result.Warnings, fmt.Sprintf("hook install: %s", installErr.Error()))
		return result, nil
	}
	// Idempotent skip ("byte-identical to current file" or "dry-run") is
	// still a success: the manifest is already in place.
	result.HooksOK = true

	if opts.Mode == claudeConnectStrict && result.Partial() {
		return result, fmt.Errorf("partial connect: gateway=%t hooks=%t", result.GatewayOK, result.HooksOK)
	}
	return result, nil
}

// disconnectClaudeCodeRuntime removes the oktsec-gateway entry via
// `claude mcp remove` and removes every Oktsec-owned hook entry (V2
// plus legacy V1) via claudecode.UninstallV2.
//
// Hook uninstall always runs, even if `claude mcp remove` failed,
// because a missing gateway entry must not block hook cleanup. The
// caller renders warnings; a non-nil error is returned when a real
// mutation failed AND when the gateway state is unprovable. A "no
// such oktsec entry" skip from the CLI is success; "we cannot run
// the CLI at all" is partial-disconnect because the gateway entry
// may still be registered.
func disconnectClaudeCodeRuntime(ctx context.Context, opts claudeCodeDisconnectOptions, deps claudeCodeLifecycleDeps) (claudeCodeLifecycleResult, error) {
	var result claudeCodeLifecycleResult

	gatewayUnprovable := false
	if !deps.hasClaudeCLI() {
		// No CLI means we cannot remove the gateway entry and we cannot
		// verify whether one exists. We still strip Oktsec-owned hooks
		// so the operator gets at least half the cleanup, but we must
		// not claim a complete disconnect.
		gatewayUnprovable = true
		result.Warnings = append(result.Warnings, "claude CLI not found on PATH; cannot remove or verify oktsec-gateway entry")
	} else {
		result.GatewayAttempted = true
		out, err := deps.runMCPRemove(ctx)
		result.GatewayOutput = string(out)
		switch {
		case err == nil:
			result.GatewayOK = true
		case isClaudeMCPAlreadyAbsent(out, err):
			// Already-absent is the success state for an idempotent
			// disconnect: the operator's intent ("no oktsec gateway
			// entry") already holds. Mark it OK and surface a warning.
			result.GatewayOK = true
			result.Warnings = append(result.Warnings, "oktsec-gateway entry was already absent")
		default:
			result.GatewayErr = fmt.Errorf("claude mcp remove: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	}

	result.HooksAttempted = true
	uninstallRes, uninstallErr := deps.uninstallHooksV2(ctx, claudecode.UninstallOptions{
		FollowSymlink:   opts.FollowSymlink,
		DryRun:          opts.DryRun,
		IncludeLegacyV1: true,
	})
	result.UninstallResult = &uninstallRes
	if uninstallErr != nil {
		result.HooksErr = uninstallErr
	} else {
		result.HooksOK = true
	}

	if result.GatewayErr != nil && result.HooksErr != nil {
		return result, fmt.Errorf("disconnect failed: gateway=%v; hooks=%v", result.GatewayErr, result.HooksErr)
	}
	if result.GatewayErr != nil {
		return result, fmt.Errorf("partial disconnect: gateway removal failed (%v); hooks were uninstalled", result.GatewayErr)
	}
	if result.HooksErr != nil {
		return result, fmt.Errorf("partial disconnect: hook uninstall failed (%v); gateway entry was removed", result.HooksErr)
	}
	if gatewayUnprovable {
		return result, fmt.Errorf("partial disconnect: claude CLI is not on PATH so the oktsec-gateway entry could not be removed or verified; install Claude Code or run `claude mcp remove oktsec-gateway` manually")
	}
	return result, nil
}

// isClaudeMCPAlreadyAbsent recognises the failure shape `claude mcp
// remove` returns when the named server was not registered. The CLI
// emits messages like "MCP server \"oktsec-gateway\" not found" with a
// non-zero exit code; we treat that as idempotent success rather than
// blocking hook cleanup behind a CLI noop.
func isClaudeMCPAlreadyAbsent(output []byte, err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(string(output))
	return strings.Contains(low, "not found") ||
		strings.Contains(low, "no such mcp server") ||
		strings.Contains(low, "is not configured")
}

// isClaudeMCPAlreadyPresent recognises the failure shape `claude mcp
// add` returns when the named server is already registered. This is
// the repair case: the operator runs `connect claude-code` again to
// fix missing/stale hooks while the gateway entry already exists.
// Treating it as idempotent success lets the helper continue into the
// hook installer instead of refusing the repair.
func isClaudeMCPAlreadyPresent(output []byte, err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(string(output))
	return strings.Contains(low, "already exists") ||
		strings.Contains(low, "already configured") ||
		strings.Contains(low, "already registered")
}
