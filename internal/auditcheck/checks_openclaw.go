package auditcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/discover"
)

// OpenClaw configuration structs — subset of fields needed for security auditing.
// Based on https://docs.openclaw.ai/gateway/security
type ocConfig struct {
	Gateway   ocGateway            `json:"gateway"`
	Tools     ocTools              `json:"tools"`
	Agents    ocAgentsConfig       `json:"agents"`
	Channels  map[string]ocChannel `json:"channels"`
	Hooks     ocHooks              `json:"hooks"`
	Logging   ocLogging            `json:"logging"`
	Discovery ocDiscovery          `json:"discovery"`
}

type ocGateway struct {
	Mode      string      `json:"mode"`
	Bind      string      `json:"bind"`
	Auth      ocAuth      `json:"auth"`
	ControlUI ocControlUI `json:"controlUi"`
}

type ocAuth struct {
	Mode  string `json:"mode"`
	Token string `json:"token"`
}

type ocControlUI struct {
	AllowInsecureAuth            bool `json:"allowInsecureAuth"`
	DangerouslyDisableDeviceAuth bool `json:"dangerouslyDisableDeviceAuth"`
}

type ocTools struct {
	Profile  string     `json:"profile"`
	Allow    []string   `json:"allow"`
	Deny     []string   `json:"deny"`
	FS       ocFS       `json:"fs"`
	Exec     ocExec     `json:"exec"`
	Elevated ocElevated `json:"elevated"`
	Browser  ocBrowser  `json:"browser"`
}

type ocFS struct {
	WorkspaceOnly *bool `json:"workspaceOnly"` // pointer: nil = default (true)
}

type ocExec struct {
	Security string `json:"security"`
}

type ocElevated struct {
	Enabled   bool     `json:"enabled"`
	AllowFrom []string `json:"allowFrom"`
}

type ocBrowser struct {
	SSRFPolicy ocSSRFPolicy `json:"ssrfPolicy"`
}

type ocSSRFPolicy struct {
	DangerouslyAllowPrivateNetwork *bool `json:"dangerouslyAllowPrivateNetwork"` // nil = default (true, unsafe)
}

type ocAgentsConfig struct {
	Defaults ocAgentDefaults `json:"defaults"`
	List     []ocAgentEntry  `json:"list"`
}

type ocAgentDefaults struct {
	Sandbox ocSandbox `json:"sandbox"`
}

type ocAgentEntry struct {
	ID      string    `json:"id"`
	Sandbox ocSandbox `json:"sandbox"`
}

type ocSandbox struct {
	Mode string `json:"mode"` // "off" | "non-main" | "all"
}

type ocChannel struct {
	DMPolicy string `json:"dmPolicy"` // "pairing" | "allowlist" | "open" | "disabled"
}

type ocHooks struct {
	Token                  string `json:"token"`
	AllowRequestSessionKey bool   `json:"allowRequestSessionKey"`
}

type ocLogging struct {
	RedactSensitive string `json:"redactSensitive"` // "off" | "tools" | "all"
}

type ocDiscovery struct {
	MDNS ocMDNS `json:"mdns"`
}

type ocMDNS struct {
	Mode string `json:"mode"` // "minimal" | "off" | "full"
}

func defaultOpenClawConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openclaw", "openclaw.json")
}

func auditOpenClaw() []Finding {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".openclaw")
	// Try both file names — OpenClaw config is JSON5 stored as .json
	for _, name := range []string{"openclaw.json", "openclaw.json5"} {
		p := filepath.Join(dir, name)
		if findings := auditOpenClawAt(p); findings != nil {
			return findings
		}
	}
	return nil
}

func auditOpenClawAt(configPath string) []Finding {
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Not installed — not an error, just skip
		return nil
	}

	clean := discover.StripJSON5Comments(data)

	var cfg ocConfig
	if err := json.Unmarshal(clean, &cfg); err != nil {
		return nil
	}

	var findings []Finding
	f := func(sev Severity, id, title, detail, remediation string) {
		findings = append(findings, Finding{
			Severity:    sev,
			CheckID:     id,
			Title:       title,
			Detail:      detail,
			Product:     "OpenClaw",
			ConfigPath:  configPath,
			Remediation: remediation,
		})
	}

	// ── Critical ──────────────────────────────────────────────

	// OC-NET-001: Gateway bind is not loopback — exposed to network
	bind := strings.ToLower(cfg.Gateway.Bind)
	if bind != "" && bind != "loopback" && bind != "localhost" && bind != "127.0.0.1" && bind != "::1" {
		f(Critical, "OC-NET-001", "Gateway exposed to network",
			fmt.Sprintf("gateway.bind is %q — the gateway accepts connections beyond localhost. "+
				"Docs recommend loopback-only. Use SSH tunnels or Tailscale for remote access.", cfg.Gateway.Bind),
			`Set gateway.bind: "loopback"`)
	}

	// OC-AUTH-001: No gateway authentication token
	if cfg.Gateway.Auth.Token == "" || cfg.Gateway.Auth.Token == "replace-with-long-random-token" {
		// Only flag if gateway is not loopback-only (remote exposure + no auth = critical)
		if bind != "" && bind != "loopback" && bind != "localhost" && bind != "127.0.0.1" {
			f(Critical, "OC-AUTH-001", "No gateway authentication token",
				"gateway.auth.token is empty or placeholder while gateway is network-exposed — "+
					"anyone on the network can control the gateway.",
				`Set gateway.auth.token to a long random value`)
		} else if cfg.Gateway.Auth.Token == "" && cfg.Gateway.Auth.Mode == "token" {
			f(Medium, "OC-AUTH-001", "Gateway auth token not set",
				"gateway.auth.mode is \"token\" but no token is configured.",
				`Set gateway.auth.token to a long random value`)
		}
	}

	// OC-EXEC-001: Exec security set to "allow" — arbitrary code execution
	if strings.ToLower(cfg.Tools.Exec.Security) == "allow" {
		f(Critical, "OC-EXEC-001", "Command execution auto-approved",
			"tools.exec.security is \"allow\" — agents can execute arbitrary shell commands "+
				"without human approval. This is the highest-risk tool setting.",
			`Set tools.exec.security: "deny" or "ask"`)
	}

	// OC-TOOL-001: Full tool profile without deny list
	if cfg.Tools.Profile == "full" && len(cfg.Tools.Deny) == 0 {
		f(Critical, "OC-TOOL-001", "Full tool profile without deny list",
			"tools.profile is \"full\" with no deny list — agents have unrestricted access "+
				"to all tools including filesystem, exec, and automation.",
			`Set tools.profile: "messaging" or add deny list`)
	}

	// ── High ─────────────────────────────────────────────────

	// OC-DM-001: Channel has open DM policy (prompt injection vector)
	for ch, chCfg := range cfg.Channels {
		if strings.ToLower(chCfg.DMPolicy) == "open" {
			f(High, "OC-DM-001", fmt.Sprintf("Open DM policy on %s channel", ch),
				fmt.Sprintf("channels.%s.dmPolicy is \"open\" — any external user can send messages "+
					"to agents. This is a prompt injection vector.", ch),
				fmt.Sprintf(`Set channels.%s.dmPolicy: "pairing" or "allowlist"`, ch))
		}
	}

	// OC-SAND-001: Sandbox disabled with exec not denied
	execDenied := false
	for _, d := range cfg.Tools.Deny {
		dl := strings.ToLower(d)
		if dl == "exec" || dl == "group:runtime" {
			execDenied = true
			break
		}
	}
	sandboxMode := strings.ToLower(cfg.Agents.Defaults.Sandbox.Mode)
	if (sandboxMode == "" || sandboxMode == "off") && !execDenied && cfg.Tools.Exec.Security != "deny" {
		f(High, "OC-SAND-001", "Sandbox disabled with exec tools available",
			"agents.defaults.sandbox.mode is \"off\" and exec tools are not denied — "+
				"agents run commands directly on the host without isolation.",
			`Set agents.defaults.sandbox.mode: "all"`)
	}

	// OC-ELEV-001: Elevated execution enabled without sender allowlist
	if cfg.Tools.Elevated.Enabled && len(cfg.Tools.Elevated.AllowFrom) == 0 {
		f(High, "OC-ELEV-001", "Elevated execution without allowFrom",
			"tools.elevated.enabled is true with no allowFrom list — any message sender "+
				"can trigger elevated (sudo-level) command execution.",
			`Disable tools.elevated or add allowFrom list`)
	}

	// OC-UI-001: Device authentication disabled on control UI
	if cfg.Gateway.ControlUI.DangerouslyDisableDeviceAuth {
		f(High, "OC-UI-001", "Device authentication disabled",
			"gateway.controlUi.dangerouslyDisableDeviceAuth is true — the web control UI "+
				"can be accessed without device verification.",
			`Set gateway.controlUi.dangerouslyDisableDeviceAuth: false`)
	}

	// OC-UI-002: Insecure auth allowed on control UI
	if cfg.Gateway.ControlUI.AllowInsecureAuth {
		f(High, "OC-UI-002", "Insecure authentication allowed",
			"gateway.controlUi.allowInsecureAuth is true — authentication can be performed "+
				"over unencrypted connections, exposing credentials.",
			`Set gateway.controlUi.allowInsecureAuth: false`)
	}

	// OC-HOOK-001: Webhook token too short or empty
	if cfg.Hooks.Token != "" && len(cfg.Hooks.Token) < 32 {
		f(High, "OC-HOOK-001", "Webhook token too short",
			fmt.Sprintf("hooks.token is only %d characters — minimum recommended is 32 for "+
				"webhook authentication security.", len(cfg.Hooks.Token)),
			`Set hooks.token to at least 32 random characters`)
	}

	// OC-PERM-001: Directory permissions > 0700
	dir := filepath.Dir(configPath)
	if info, err := os.Stat(dir); err == nil {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			f(High, "OC-PERM-001", "OpenClaw directory has loose permissions",
				fmt.Sprintf("%s has mode %04o — group/world accessible. "+
					"Config files may contain auth tokens.", dir, mode),
				fmt.Sprintf("chmod 700 %s", dir))
		}
	}

	// ── Medium ───────────────────────────────────────────────

	// OC-FS-001: Workspace-only filesystem disabled
	if cfg.Tools.FS.WorkspaceOnly != nil && !*cfg.Tools.FS.WorkspaceOnly {
		f(Medium, "OC-FS-001", "Filesystem access not restricted to workspace",
			"tools.fs.workspaceOnly is false — agents can read and write files "+
				"outside the workspace directory.",
			`Set tools.fs.workspaceOnly: true`)
	}

	// OC-LOG-001: Sensitive data redaction disabled
	if strings.ToLower(cfg.Logging.RedactSensitive) == "off" {
		f(Medium, "OC-LOG-001", "Sensitive data redaction disabled",
			"logging.redactSensitive is \"off\" — tool inputs/outputs containing "+
				"secrets or PII are written to logs in plaintext.",
			`Set logging.redactSensitive: "tools" or "all"`)
	}

	// OC-DISC-001: mDNS broadcasting full system info
	if strings.ToLower(cfg.Discovery.MDNS.Mode) == "full" {
		f(Medium, "OC-DISC-001", "mDNS broadcasting full system info",
			"discovery.mdns.mode is \"full\" — the gateway broadcasts CLI path and SSH port "+
				"to the local network via mDNS.",
			`Set discovery.mdns.mode: "minimal" or "off"`)
	}

	// OC-HOOK-002: External session key selection allowed
	if cfg.Hooks.AllowRequestSessionKey {
		f(Medium, "OC-HOOK-002", "External session key selection allowed",
			"hooks.allowRequestSessionKey is true — external webhook callers can choose "+
				"which session receives their message, potentially hijacking sessions.",
			`Set hooks.allowRequestSessionKey: false`)
	}

	// OC-SSRF-001: SSRF private network access allowed
	if cfg.Tools.Browser.SSRFPolicy.DangerouslyAllowPrivateNetwork != nil &&
		*cfg.Tools.Browser.SSRFPolicy.DangerouslyAllowPrivateNetwork {
		f(Medium, "OC-SSRF-001", "Browser allows private network requests",
			"tools.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is true — "+
				"agents can make HTTP requests to internal/private network addresses.",
			`Set tools.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: false`)
	}

	// OC-PERM-002: Config file permissions > 0600
	if info, err := os.Stat(configPath); err == nil {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			f(Medium, "OC-PERM-002", "OpenClaw config has loose permissions",
				fmt.Sprintf("%s has mode %04o — group/world readable. "+
					"File may contain auth tokens and credentials.", configPath, mode),
				fmt.Sprintf("chmod 600 %s", configPath))
		}
	}

	// ── Info ─────────────────────────────────────────────────

	// OC-INFO-001: Configuration summary
	agentCount := len(cfg.Agents.List)
	channelCount := len(cfg.Channels)
	profile := cfg.Tools.Profile
	if profile == "" {
		profile = "messaging"
	}
	f(Info, "OC-INFO-001", "OpenClaw configuration summary",
		fmt.Sprintf("Gateway mode: %s, bind: %s, tool profile: %s, "+
			"%d agents, %d channels, sandbox: %s",
			orDefault(cfg.Gateway.Mode, "local"),
			orDefault(cfg.Gateway.Bind, "loopback"),
			profile, agentCount, channelCount,
			orDefault(cfg.Agents.Defaults.Sandbox.Mode, "off")),
		"")

	return findings
}

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

// AuditOpenClawSandbox returns findings from a deliberately insecure OpenClaw
// config. Used by the dashboard sandbox route to test the audit UI without
// requiring OpenClaw to be installed.
func AuditOpenClawSandbox() []Finding {
	dir, err := os.MkdirTemp("", "oktsec-oc-sandbox-*")
	if err != nil {
		return nil
	}
	defer func() { _ = os.RemoveAll(dir) }()

	configPath := filepath.Join(dir, "openclaw.json")
	sampleConfig := `{
  "gateway": {
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": ""
    },
    "controlUi": {
      "allowInsecureAuth": true,
      "dangerouslyDisableDeviceAuth": true
    }
  },
  "tools": {
    "profile": "full",
    "exec": { "security": "allow" },
    "fs": { "workspaceOnly": false },
    "elevated": { "enabled": true },
    "browser": {
      "ssrfPolicy": { "dangerouslyAllowPrivateNetwork": true }
    }
  },
  "agents": {
    "defaults": { "sandbox": { "mode": "off" } },
    "list": [
      { "id": "code-agent" },
      { "id": "research-agent" }
    ]
  },
  "channels": {
    "slack":    { "dmPolicy": "open" },
    "discord":  { "dmPolicy": "open" },
    "telegram": { "dmPolicy": "pairing" }
  },
  "hooks": {
    "token": "short-tok",
    "allowRequestSessionKey": true
  },
  "logging": {
    "redactSensitive": "off"
  },
  "discovery": {
    "mdns": { "mode": "full" }
  }
}`

	if err := os.WriteFile(configPath, []byte(sampleConfig), 0o644); err != nil {
		return nil
	}
	// Make dir world-readable to trigger OC-PERM-001
	_ = os.Chmod(dir, 0o755)

	return auditOpenClawAt(configPath)
}
