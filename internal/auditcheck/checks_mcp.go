package auditcheck

import (
	"fmt"
	"strings"

	"github.com/oktsec/oktsec/internal/discover"
)

// suspiciousCommands are commands that should not appear in MCP server configs.
var suspiciousCommands = []string{"curl", "wget", "nc", "bash -c", "eval"}

// secretEnvKeys are substrings in env var names that indicate plaintext secrets.
var secretEnvKeys = []string{"TOKEN", "SECRET", "KEY", "PASSWORD", "API_KEY"}

// mcpScanFunc is the function used to discover MCP servers.
// Override in tests to avoid scanning real host configs.
var mcpScanFunc = discover.Scan

func auditMCPServers() []Finding {
	result, err := mcpScanFunc()
	if err != nil || result == nil || result.TotalServers() == 0 {
		return nil
	}
	return auditMCPServersFromResult(result)
}

func auditMCPServersFromResult(result *discover.Result) []Finding {
	var findings []Finding
	f := func(sev Severity, id, title, detail, remediation string) {
		findings = append(findings, Finding{
			Severity:    sev,
			CheckID:     id,
			Title:       title,
			Detail:      detail,
			Product:     "MCP Servers",
			Remediation: remediation,
		})
	}

	totalServers := 0
	for _, cr := range result.Clients {
		for _, srv := range cr.Servers {
			totalServers++

			// MCP-001: Suspicious command
			cmdFull := srv.Command
			if len(srv.Args) > 0 {
				cmdFull += " " + strings.Join(srv.Args, " ")
			}
			cmdLower := strings.ToLower(cmdFull)
			for _, sus := range suspiciousCommands {
				if strings.Contains(cmdLower, sus) {
					f(High, "MCP-001",
						fmt.Sprintf("Suspicious MCP server command: %s", srv.Name),
						fmt.Sprintf("Server %q in %s uses %q which contains %q — may indicate a malicious or misconfigured server.",
							srv.Name, discover.ClientDisplayName(cr.Client), cmdFull, sus),
						"Review the MCP server command and replace with a trusted binary")
					break
				}
			}
			// Also check for pipe
			if strings.Contains(cmdFull, "|") {
				f(High, "MCP-001",
					fmt.Sprintf("Suspicious MCP server command: %s", srv.Name),
					fmt.Sprintf("Server %q in %s uses a pipe in its command %q — may indicate command chaining.",
						srv.Name, discover.ClientDisplayName(cr.Client), cmdFull),
					"Review the MCP server command and avoid piped commands")
			}

			// MCP-002: Env var secrets in plaintext
			for envKey := range srv.Env {
				upper := strings.ToUpper(envKey)
				for _, secretKey := range secretEnvKeys {
					if strings.Contains(upper, secretKey) {
						f(Medium, "MCP-002",
							fmt.Sprintf("Plaintext secret in MCP config: %s", envKey),
							fmt.Sprintf("Server %q in %s has env var %q which appears to contain a secret stored in plaintext config.",
								srv.Name, discover.ClientDisplayName(cr.Client), envKey),
							"Use environment variable references or a secrets manager instead of plaintext values")
						break
					}
				}
			}

			// MCP-004: Command with no args (bare wrapper)
			if srv.Command != "" && len(srv.Args) == 0 && !strings.Contains(srv.Command, " ") {
				f(High, "MCP-004",
					fmt.Sprintf("MCP server with bare command: %s", srv.Name),
					fmt.Sprintf("Server %q in %s runs %q with no arguments — may be a wrapper hiding the real command.",
						srv.Name, discover.ClientDisplayName(cr.Client), srv.Command),
					"Verify the command is a trusted MCP server binary")
			}
		}
	}

	// MCP-003: Excessive server count
	if totalServers > 20 {
		f(Medium, "MCP-003",
			fmt.Sprintf("Excessive MCP server count: %d", totalServers),
			fmt.Sprintf("Found %d MCP servers across %d clients — a large attack surface. Review and remove unused servers.",
				totalServers, result.TotalClients()),
			"Remove unused MCP server configurations")
	}

	// MCP-005: Summary (always emitted)
	f(Info, "MCP-005",
		"MCP discovery summary",
		fmt.Sprintf("Found %d MCP servers across %d clients.", totalServers, result.TotalClients()),
		"")

	return findings
}
