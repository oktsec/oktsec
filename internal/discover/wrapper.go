package discover

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapClient modifies a client's MCP config to route servers through oktsec proxy.
// It saves a backup of the original config as <path>.bak.
func WrapClient(clientName string) (wrapped int, err error) {
	clients := KnownClients()
	var configPath string

	for _, c := range clients {
		if c.Name == clientName {
			for _, p := range c.Paths {
				if _, err := os.Stat(p); err == nil {
					configPath = p
					break
				}
			}
			break
		}
	}

	if configPath == "" {
		return 0, fmt.Errorf("no config found for client %q", clientName)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0, fmt.Errorf("reading config: %w", err)
	}

	// Save backup
	backupPath := configPath + ".bak"
	if err := os.WriteFile(backupPath, data, 0o644); err != nil {
		return 0, fmt.Errorf("writing backup: %w", err)
	}

	// Parse config
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return 0, fmt.Errorf("parsing config: %w", err)
	}

	serversRaw, ok := raw["mcpServers"]
	if !ok {
		return 0, fmt.Errorf("no mcpServers key in config")
	}

	var servers map[string]mcpServerJSON
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		return 0, fmt.Errorf("parsing mcpServers: %w", err)
	}

	// Wrap each server
	for name, srv := range servers {
		if srv.Command == "oktsec" {
			continue // Already wrapped
		}

		newArgs := []string{"proxy", "--agent", name, "--"}
		newArgs = append(newArgs, srv.Command)
		newArgs = append(newArgs, srv.Args...)

		srv.Command = "oktsec"
		srv.Args = newArgs
		servers[name] = srv
		wrapped++
	}

	// Marshal back
	serversJSON, err := json.MarshalIndent(servers, "  ", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshaling servers: %w", err)
	}
	raw["mcpServers"] = serversJSON

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, append(out, '\n'), 0o644); err != nil {
		return 0, fmt.Errorf("writing config: %w", err)
	}

	return wrapped, nil
}

// UnwrapClient restores the original MCP config from the .bak backup.
func UnwrapClient(clientName string) error {
	clients := KnownClients()
	var configPath string

	for _, c := range clients {
		if c.Name == clientName {
			for _, p := range c.Paths {
				if _, err := os.Stat(p); err == nil {
					configPath = p
					break
				}
			}
			break
		}
	}

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
