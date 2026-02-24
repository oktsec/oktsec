package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/discover"
)

// OpenClaw config structs (local subset of fields we need for auditing).
type ocAuditConfig struct {
	Gateway  ocAuditGateway          `json:"gateway"`
	Agents   map[string]ocAuditAgent `json:"agents"`
	Tools    ocAuditTools            `json:"tools"`
	DMPolicy string                  `json:"dmPolicy"`
	Include  []string                `json:"$include"`
}

type ocAuditGateway struct {
	Bind string `json:"bind"`
}

type ocAuditAgent struct {
	Sandbox bool `json:"sandbox"`
}

type ocAuditTools struct {
	Profile string   `json:"profile"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
}

func defaultOpenClawConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openclaw", "openclaw.json")
}

func auditOpenClaw() []AuditFinding {
	return auditOpenClawAt(defaultOpenClawConfigPath())
}

func auditOpenClawAt(configPath string) []AuditFinding {
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Not installed — not an error, just skip
		return nil
	}

	clean := discover.StripJSON5Comments(data)

	var cfg ocAuditConfig
	if err := json.Unmarshal(clean, &cfg); err != nil {
		return nil
	}

	var findings []AuditFinding
	f := func(sev AuditSeverity, id, title, detail string) {
		findings = append(findings, AuditFinding{
			Severity: sev,
			CheckID:  id,
			Title:    title,
			Detail:   detail,
			Product:  "OpenClaw",
		})
	}

	// OC-001: Gateway exposed to network
	bind := strings.ToLower(cfg.Gateway.Bind)
	if bind == "0.0.0.0" || bind == "::" || bind == "lan" {
		f(AuditCritical, "OC-001", "Gateway exposed to network",
			fmt.Sprintf("gateway.bind is %q — the WebSocket gateway accepts connections from any host. Set gateway.bind: \"127.0.0.1\".", cfg.Gateway.Bind))
	}

	// OC-002: Full tool profile without deny list
	if cfg.Tools.Profile == "full" && len(cfg.Tools.Deny) == 0 {
		f(AuditCritical, "OC-002", "Full tool profile without deny list",
			"tools.profile is \"full\" with no deny list — agents have unrestricted tool access. Add a tools.deny list or use a restrictive profile.")
	}

	// OC-003: Exec/shell tools without sandboxed agents
	hasDangerous := false
	for _, t := range cfg.Tools.Allow {
		tl := strings.ToLower(t)
		if tl == "exec" || tl == "shell" || tl == "terminal" || tl == "bash" {
			hasDangerous = true
			break
		}
	}
	if hasDangerous {
		anySandbox := false
		for _, a := range cfg.Agents {
			if a.Sandbox {
				anySandbox = true
				break
			}
		}
		if !anySandbox {
			f(AuditCritical, "OC-003", "Exec/shell tools without sandboxed agents",
				"Exec or shell tools are allowed but no agents have sandbox enabled — arbitrary code execution risk.")
		}
	}

	// OC-004: Open DM policy
	if strings.ToLower(cfg.DMPolicy) == "open" {
		f(AuditHigh, "OC-004", "Open DM policy",
			"dmPolicy is \"open\" — any external message can reach agents. This is a prompt injection vector. Set dmPolicy: \"restricted\".")
	}

	// OC-005: $include with path traversal
	for _, inc := range cfg.Include {
		if strings.Contains(inc, "..") {
			f(AuditCritical, "OC-005", "Path traversal in $include",
				fmt.Sprintf("$include contains %q with path traversal — could load config from outside the expected directory.", inc))
			break
		}
	}

	// OC-006: No agents have sandbox enabled
	if len(cfg.Agents) > 0 {
		allUnsandboxed := true
		for _, a := range cfg.Agents {
			if a.Sandbox {
				allUnsandboxed = false
				break
			}
		}
		if allUnsandboxed {
			f(AuditHigh, "OC-006", "No agents have sandbox enabled",
				"All agents run with full host access. Enable sandbox on at least one agent.")
		}
	}

	// OC-007: Directory permissions > 0700
	dir := filepath.Dir(configPath)
	if info, err := os.Stat(dir); err == nil {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			f(AuditHigh, "OC-007", "OpenClaw directory has loose permissions",
				fmt.Sprintf("%s has mode %04o — group/world accessible. Run: chmod 700 %s", dir, mode, dir))
		}
	}

	// OC-008: Config file permissions > 0600
	if info, err := os.Stat(configPath); err == nil {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			f(AuditMedium, "OC-008", "OpenClaw config has loose permissions",
				fmt.Sprintf("%s has mode %04o — group/world readable. Run: chmod 600 %s", configPath, mode, configPath))
		}
	}

	return findings
}
