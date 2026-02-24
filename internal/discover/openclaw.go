package discover

import (
	"encoding/json"
	"os"
	"strings"
)

// openClawConfig represents the JSON5 configuration for OpenClaw.
type openClawConfig struct {
	Gateway  ocGateway          `json:"gateway"`
	Agents   map[string]ocAgent `json:"agents"`
	Tools    ocTools            `json:"tools"`
	Channels map[string]any     `json:"channels"`
	DMPolicy string             `json:"dmPolicy"`
	Include  []string           `json:"$include"`
}

type ocGateway struct {
	Port int    `json:"port"`
	Bind string `json:"bind"`
	Auth string `json:"auth"`
}

type ocTools struct {
	Profile string   `json:"profile"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
}

type ocAgent struct {
	Sandbox bool `json:"sandbox"`
}

// OpenClawRisk holds the assessed risk for an OpenClaw installation.
type OpenClawRisk struct {
	Level   string // critical, high, medium, low
	Reasons []string
}

// scanOpenClawConfig parses an OpenClaw config file and maps it to ClientResult
// for compatibility with the existing discovery model.
func scanOpenClawConfig(path string) (*ClientResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	clean := StripJSON5Comments(data)

	var cfg openClawConfig
	if err := json.Unmarshal(clean, &cfg); err != nil {
		return nil, err
	}

	var servers []MCPServer

	// Map the gateway as a server entry
	bind := cfg.Gateway.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	servers = append(servers, MCPServer{
		Name:    "openclaw-gateway",
		Command: "openclaw",
		Args:    []string{"gateway", bind},
	})

	// Map each agent as a server entry
	for name := range cfg.Agents {
		servers = append(servers, MCPServer{
			Name:    name,
			Command: "openclaw",
			Args:    []string{"agent", name},
		})
	}

	// Map channels as server entries
	for name := range cfg.Channels {
		servers = append(servers, MCPServer{
			Name:    "channel-" + name,
			Command: "openclaw",
			Args:    []string{"channel", name},
		})
	}

	return &ClientResult{
		Client:  "openclaw",
		Path:    path,
		Servers: servers,
	}, nil
}

// StripJSON5Comments removes // and /* */ comments from JSON5 data,
// being careful not to strip inside string literals.
func StripJSON5Comments(data []byte) []byte {
	var out []byte
	i := 0
	n := len(data)

	for i < n {
		// String literal — copy verbatim
		if data[i] == '"' {
			out = append(out, data[i])
			i++
			for i < n {
				if data[i] == '\\' && i+1 < n {
					out = append(out, data[i], data[i+1])
					i += 2
					continue
				}
				out = append(out, data[i])
				if data[i] == '"' {
					i++
					break
				}
				i++
			}
			continue
		}

		// Line comment
		if i+1 < n && data[i] == '/' && data[i+1] == '/' {
			i += 2
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		}

		// Block comment
		if i+1 < n && data[i] == '/' && data[i+1] == '*' {
			i += 2
			for i+1 < n {
				if data[i] == '*' && data[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		out = append(out, data[i])
		i++
	}

	return out
}

// AssessOpenClawRisk checks an OpenClaw config for security risks.
func AssessOpenClawRisk(path string) (*OpenClawRisk, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	clean := StripJSON5Comments(data)

	var cfg openClawConfig
	if err := json.Unmarshal(clean, &cfg); err != nil {
		return nil, err
	}

	risk := &OpenClawRisk{Level: "low"}
	var reasons []string

	// 1. Full tool profile without deny list
	if cfg.Tools.Profile == "full" && len(cfg.Tools.Deny) == 0 {
		reasons = append(reasons, "tools.profile is \"full\" with no deny list — agents have unrestricted tool access")
		risk.Level = "critical"
	}

	// 2. Exec/shell in allow without sandbox
	hasDangerousTool := false
	for _, t := range cfg.Tools.Allow {
		tl := strings.ToLower(t)
		if tl == "exec" || tl == "shell" || tl == "terminal" || tl == "bash" {
			hasDangerousTool = true
			break
		}
	}
	if hasDangerousTool {
		anySandbox := false
		for _, a := range cfg.Agents {
			if a.Sandbox {
				anySandbox = true
				break
			}
		}
		if !anySandbox {
			reasons = append(reasons, "exec/shell tool allowed without any sandboxed agents — arbitrary code execution risk")
			risk.Level = "critical"
		}
	}

	// 3. Gateway exposed to network
	bind := strings.ToLower(cfg.Gateway.Bind)
	if bind == "0.0.0.0" || bind == "lan" || bind == "::" {
		reasons = append(reasons, "gateway.bind is \""+cfg.Gateway.Bind+"\" — WebSocket gateway exposed to network")
		risk.Level = elevate(risk.Level, "high")
	}

	// 4. Open DM policy
	if strings.ToLower(cfg.DMPolicy) == "open" {
		reasons = append(reasons, "dmPolicy is \"open\" — any external message can reach agents (prompt injection vector)")
		risk.Level = elevate(risk.Level, "high")
	}

	// 5. Path traversal in $include
	for _, inc := range cfg.Include {
		if strings.Contains(inc, "..") {
			reasons = append(reasons, "$include contains path traversal: "+inc)
			risk.Level = "critical"
			break
		}
	}

	// 6. Messaging channels configured
	if len(cfg.Channels) > 0 {
		var names []string
		for name := range cfg.Channels {
			names = append(names, name)
		}
		reasons = append(reasons, "messaging channels configured ("+strings.Join(names, ", ")+") — each is a prompt injection attack surface")
		risk.Level = elevate(risk.Level, "medium")
	}

	// 7. No agents have sandbox enabled
	if len(cfg.Agents) > 0 {
		allUnsandboxed := true
		for _, a := range cfg.Agents {
			if a.Sandbox {
				allUnsandboxed = false
				break
			}
		}
		if allUnsandboxed {
			reasons = append(reasons, "no agents have sandbox enabled — all agents run with full host access")
			risk.Level = elevate(risk.Level, "high")
		}
	}

	risk.Reasons = reasons
	return risk, nil
}

// elevate returns the higher severity between current and candidate.
func elevate(current, candidate string) string {
	order := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}
