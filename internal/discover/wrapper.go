package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// WrapOpts controls how servers are wrapped.
type WrapOpts struct {
	Enforce    bool   // Include --enforce flag in proxy commands
	ConfigPath string // Absolute path to oktsec.yaml (passed as --config to proxy)
}

// WrapClient modifies a client's MCP config to route servers through oktsec proxy.
// It saves a backup of the original config as <path>.bak.
func WrapClient(clientName string, opts WrapOpts) (wrapped int, err error) {
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

	wrapped = wrapServers(servers, opts)

	return wrapped, writeMCPConfig(configPath, raw, servers)
}

// WrapAllClients wraps all discovered clients that support stdio wrapping.
// Returns per-client results.
func WrapAllClients(opts WrapOpts) []WrapResult {
	var results []WrapResult
	result, err := Scan()
	if err != nil {
		return nil
	}

	for _, cr := range result.Clients {
		if !isWrappable(cr.Client) {
			continue
		}
		if len(cr.Servers) == 0 {
			continue
		}
		wrapped, err := WrapClient(cr.Client, opts)
		r := WrapResult{
			Client:  cr.Client,
			Path:    cr.Path,
			Servers: len(cr.Servers),
			Wrapped: wrapped,
		}
		if err != nil {
			errStr := err.Error()
			r.Error = &errStr
		}
		results = append(results, r)
	}
	return results
}

// WrapResult holds the outcome of wrapping a single client.
type WrapResult struct {
	Client  string
	Path    string
	Servers int
	Wrapped int
	Error   *string
}

// WrappableClients returns client names that support stdio wrapping.
func WrappableClients() []string {
	return []string{
		"claude-desktop", "cursor", "vscode", "cline", "windsurf",
		"amp", "gemini-cli", "copilot-cli", "amazon-q",
		"roo-code", "kilo-code", "boltai", "jetbrains",
	}
}

func isWrappable(client string) bool {
	for _, c := range WrappableClients() {
		if c == client {
			return true
		}
	}
	return false
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

func wrapServers(servers map[string]mcpServerJSON, opts WrapOpts) int {
	wrapped := 0
	for name, srv := range servers {
		if srv.Command == "oktsec" {
			continue
		}
		newArgs := []string{"proxy"}
		if opts.ConfigPath != "" {
			absPath, err := filepath.Abs(opts.ConfigPath)
			if err == nil {
				opts.ConfigPath = absPath
			}
			newArgs = append(newArgs, "--config", opts.ConfigPath)
		}
		newArgs = append(newArgs, "--agent", name)
		if opts.Enforce {
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
