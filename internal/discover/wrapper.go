package discover

import (
	"encoding/json"
	"fmt"
	"os"
)

// findClientConfig returns the config file path for a client, or empty string if not found.
func findClientConfig(clientName string) string {
	for _, c := range KnownClients() {
		if c.Name == clientName {
			for _, p := range c.Paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	return ""
}

// WrapClient modifies a client's MCP config to route servers through oktsec proxy.
// It saves a backup of the original config as <path>.bak.
func WrapClient(clientName string) (wrapped int, err error) {
	configPath := findClientConfig(clientName)
	if configPath == "" {
		return 0, fmt.Errorf("no config found for client %q", clientName)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0, fmt.Errorf("reading config: %w", err)
	}

	if err := os.WriteFile(configPath+".bak", data, 0o644); err != nil {
		return 0, fmt.Errorf("writing backup: %w", err)
	}

	raw, servers, err := parseMCPConfig(data)
	if err != nil {
		return 0, err
	}

	wrapped = wrapServers(servers)

	return wrapped, writeMCPConfig(configPath, raw, servers)
}

func parseMCPConfig(data []byte) (map[string]json.RawMessage, map[string]mcpServerJSON, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parsing config: %w", err)
	}
	serversRaw, ok := raw["mcpServers"]
	if !ok {
		return nil, nil, fmt.Errorf("no mcpServers key in config")
	}
	var servers map[string]mcpServerJSON
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		return nil, nil, fmt.Errorf("parsing mcpServers: %w", err)
	}
	return raw, servers, nil
}

// WrapServersWithEnforce controls whether --enforce flag is included.
var WrapServersWithEnforce bool

func wrapServers(servers map[string]mcpServerJSON) int {
	wrapped := 0
	for name, srv := range servers {
		if srv.Command == "oktsec" {
			continue
		}
		newArgs := []string{"proxy", "--agent", name}
		if WrapServersWithEnforce {
			newArgs = append(newArgs, "--enforce")
		}
		newArgs = append(newArgs, "--")
		newArgs = append(newArgs, srv.Command)
		newArgs = append(newArgs, srv.Args...)
		srv.Command = "oktsec"
		srv.Args = newArgs
		servers[name] = srv
		wrapped++
	}
	return wrapped
}

func writeMCPConfig(path string, raw map[string]json.RawMessage, servers map[string]mcpServerJSON) error {
	serversJSON, err := json.MarshalIndent(servers, "  ", "  ")
	if err != nil {
		return fmt.Errorf("marshaling servers: %w", err)
	}
	raw["mcpServers"] = serversJSON

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// UnwrapClient restores the original MCP config from the .bak backup.
func UnwrapClient(clientName string) error {
	configPath := findClientConfig(clientName)
	if configPath == "" {
		return fmt.Errorf("no config found for client %q", clientName)
	}

	backupPath := configPath + ".bak"
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("no backup found at %s — nothing to restore", backupPath)
	}

	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		return fmt.Errorf("restoring config: %w", err)
	}

	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("removing backup: %w", err)
	}

	return nil
}

// ClientConfigPath returns the config file path for a client, or empty string if not found.
func ClientConfigPath(clientName string) string {
	return findClientConfig(clientName)
}
