package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hand-edited oktsec.yaml must not be able to smuggle a path
// traversal into the agents map. config.Load goes through Validate,
// which calls identity.ValidatePrincipalName on every agent key. These
// tests pin that contract.

func TestLoad_RejectsUnsafeAgentMapKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	yaml := strings.TrimLeft(`
version: "1"
server:
  port: 8080
identity:
  keys_dir: ./keys
  require_signature: false
agents:
  "../../evil":
    can_message: ["*"]
`, "\n")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatalf("Load accepted an agents map key that escapes the keys directory")
	}
}

func TestLoad_RejectsUnsafeMCPServerMapKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	yaml := strings.TrimLeft(`
version: "1"
server:
  port: 8080
identity:
  keys_dir: ./keys
  require_signature: false
gateway:
  enabled: true
  port: 9090
mcp_servers:
  "../escape":
    transport: stdio
    command: echo
`, "\n")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatalf("Load accepted an mcp_servers map key that escapes the keys directory")
	}
}

func TestLoad_AcceptsValidAgentNames(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	yaml := strings.TrimLeft(`
version: "1"
server:
  port: 8080
identity:
  keys_dir: ./keys
  require_signature: false
agents:
  filesystem: { can_message: ["*"] }
  github: { can_message: ["*"] }
  research-agent: { can_message: ["*"] }
  agent_01: { can_message: ["*"] }
  org.tool: { can_message: ["*"] }
`, "\n")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(%s) returned %v on a valid config", cfgPath, err)
	}
	for _, want := range []string{"filesystem", "github", "research-agent", "agent_01", "org.tool"} {
		if _, ok := cfg.Agents[want]; !ok {
			t.Fatalf("Load dropped a valid agent name %q", want)
		}
	}
}
