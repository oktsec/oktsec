package discover

import (
	"os"
	"path/filepath"
	"runtime"
)

// Client represents a known MCP client application.
type Client struct {
	Name  string
	Paths []string // Config file paths to check
}

// KnownClients returns all supported MCP client applications with their config paths.
func KnownClients() []Client {
	home, _ := os.UserHomeDir()
	clients := []Client{
		{
			Name:  "claude-desktop",
			Paths: claudeDesktopPaths(home),
		},
		{
			Name:  "cursor",
			Paths: []string{filepath.Join(home, ".cursor", "mcp.json")},
		},
		{
			Name:  "vscode",
			Paths: []string{filepath.Join(home, ".vscode", "mcp.json")},
		},
		{
			Name:  "cline",
			Paths: []string{filepath.Join(home, ".cline", "mcp_settings.json")},
		},
		{
			Name:  "windsurf",
			Paths: []string{filepath.Join(home, ".windsurf", "mcp.json")},
		},
		{
			Name:  "openclaw",
			Paths: []string{filepath.Join(home, ".openclaw", "openclaw.json")},
		},
	}
	return clients
}

func claudeDesktopPaths(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{
			filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
		}
	default:
		return nil
	}
}
