package auditcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type nanoClawAllowlist struct {
	AllowedRoots    []nanoClawRoot `json:"allowedRoots"`
	BlockedPatterns []string       `json:"blockedPatterns"`
	NonMainReadOnly bool           `json:"nonMainReadOnly"`
}

type nanoClawRoot struct {
	Path           string `json:"path"`
	AllowReadWrite bool   `json:"allowReadWrite"`
	Description    string `json:"description,omitempty"`
}

func defaultNanoClawConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "nanoclaw")
}

func defaultNanoClawAllowlistPath() string {
	return filepath.Join(defaultNanoClawConfigDir(), "mount-allowlist.json")
}

func auditNanoClaw() []Finding {
	return auditNanoClawAt(defaultNanoClawAllowlistPath())
}

func auditNanoClawAt(allowlistPath string) []Finding {
	configDir := filepath.Dir(allowlistPath)

	// Check if the config directory exists at all — if not, NanoClaw is not installed
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return nil
	}

	var findings []Finding
	f := func(sev Severity, id, title, detail, remediation string) {
		findings = append(findings, Finding{
			Severity:    sev,
			CheckID:     id,
			Title:       title,
			Detail:      detail,
			Product:     "NanoClaw",
			ConfigPath:  allowlistPath,
			Remediation: remediation,
		})
	}

	// NC-MNT-001: Mount allowlist file missing
	data, err := os.ReadFile(allowlistPath)
	if err != nil {
		f(High, "NC-MNT-001", "Mount allowlist missing",
			fmt.Sprintf("NanoClaw config directory exists but %s is missing — no mount security is configured.", allowlistPath),
			"Create mount-allowlist.json")
		return findings
	}

	var allowlist nanoClawAllowlist
	if err := json.Unmarshal(data, &allowlist); err != nil {
		f(High, "NC-MNT-001", "Mount allowlist unparseable",
			fmt.Sprintf("Cannot parse %s: %v", allowlistPath, err),
			"Create mount-allowlist.json")
		return findings
	}

	// NC-MNT-002: nonMainReadOnly is false
	if !allowlist.NonMainReadOnly {
		f(High, "NC-MNT-002", "Non-main groups have write access",
			"nonMainReadOnly is false — non-main groups can write to mounted paths. Set nonMainReadOnly: true.",
			`Set "nonMainReadOnly": true`)
	}

	// NC-MNT-003: Dangerous root paths
	home, _ := os.UserHomeDir()
	for _, root := range allowlist.AllowedRoots {
		p := root.Path
		// Expand ~ and $HOME
		expanded := p
		if strings.HasPrefix(expanded, "~") {
			expanded = filepath.Join(home, expanded[1:])
		}
		expanded = os.ExpandEnv(expanded)
		expanded = filepath.Clean(expanded)

		if expanded == "/" || expanded == home || p == "~" || p == "$HOME" {
			f(Critical, "NC-MNT-003", fmt.Sprintf("Dangerous mount root: %s", p),
				fmt.Sprintf("Allowed root %q resolves to %q — agent can reach the entire directory tree. Restrict to specific subdirectories.", p, expanded),
				"Replace root path with specific subdirectory")
		}
	}

	// NC-MNT-004: No custom blocked patterns
	if len(allowlist.BlockedPatterns) == 0 {
		f(Medium, "NC-MNT-004", "No blocked patterns configured",
			"blockedPatterns is empty — no file patterns are blocked from agent access. Add patterns like \"*.env\", \".ssh/*\".",
			`Add "blockedPatterns": ["*.env", ".ssh/*"]`)
	}

	// NC-SEC-001: Allowlist file permissions > 0600
	if info, err := os.Stat(allowlistPath); err == nil {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			f(High, "NC-SEC-001", "Allowlist file has loose permissions",
				fmt.Sprintf("%s has mode %04o — group/world accessible (tamper risk). Run: chmod 600 %s", allowlistPath, mode, allowlistPath),
				fmt.Sprintf("chmod 600 %s", allowlistPath))
		}
	}

	// NC-MNT-005: allowReadWrite on sensitive paths
	sensitivePaths := []string{home, "/etc", "/var"}
	for _, root := range allowlist.AllowedRoots {
		if !root.AllowReadWrite {
			continue
		}
		expanded := root.Path
		if strings.HasPrefix(expanded, "~") {
			expanded = filepath.Join(home, expanded[1:])
		}
		expanded = os.ExpandEnv(expanded)
		expanded = filepath.Clean(expanded)

		for _, sp := range sensitivePaths {
			if expanded == sp || strings.HasPrefix(expanded, sp+string(filepath.Separator)) {
				f(High, "NC-MNT-005", fmt.Sprintf("Read-write mount on sensitive path: %s", root.Path),
					fmt.Sprintf("Allowed root %q has allowReadWrite: true and overlaps with %s. Use read-only access for sensitive paths.", root.Path, sp),
					`Set "allowReadWrite": false on sensitive paths`)
				break
			}
		}
	}

	// NC-MNT-006: Allowlist stats (info)
	rwCount := 0
	for _, r := range allowlist.AllowedRoots {
		if r.AllowReadWrite {
			rwCount++
		}
	}
	f(Info, "NC-MNT-006", "NanoClaw mount allowlist summary",
		fmt.Sprintf("%d allowed roots (%d read-write), %d blocked patterns, nonMainReadOnly: %v",
			len(allowlist.AllowedRoots), rwCount, len(allowlist.BlockedPatterns), allowlist.NonMainReadOnly),
		"")

	return findings
}
