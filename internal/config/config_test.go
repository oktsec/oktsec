package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	content := `
version: "1"
server:
  port: 9090
  log_level: debug
identity:
  keys_dir: ./test-keys
  require_signature: false
agents:
  agent-a:
    can_message: [agent-b]
rules:
  - id: test-rule
    severity: high
    action: block
`
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cfg.Server.LogLevel)
	}
	if cfg.Identity.RequireSignature {
		t.Error("require_signature should be false")
	}
	if len(cfg.Agents) != 1 {
		t.Errorf("agents = %d, want 1", len(cfg.Agents))
	}
	if len(cfg.Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(cfg.Rules))
	}
}

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Server.Port != 8080 {
		t.Errorf("default port = %d, want 8080", cfg.Server.Port)
	}
	if !cfg.Identity.RequireSignature {
		t.Error("default require_signature should be true")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should not error: %v", err)
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Port = 0
	if err := cfg.Validate(); err == nil {
		t.Error("port 0 should be invalid")
	}
}

func TestValidate_MissingKeysDir(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Port: 8080},
		Identity: IdentityConfig{RequireSignature: true, KeysDir: ""},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("missing keys_dir with require_signature=true should be invalid")
	}
}

func TestValidate_SelfMessage(t *testing.T) {
	cfg := Defaults()
	cfg.Agents = map[string]Agent{
		"a": {CanMessage: []string{"a"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("agent messaging itself should be invalid")
	}
}

func TestValidate_InvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleAction{{ID: "test", Action: "invalid"}}
	if err := cfg.Validate(); err == nil {
		t.Error("invalid action should be invalid")
	}
}

func TestAgentMetadataRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")

	cfg := Defaults()
	cfg.Agents["test-agent"] = Agent{
		CanMessage:  []string{"other-agent"},
		Description: "A test agent",
		CreatedBy:   "dashboard",
		CreatedAt:   "2026-02-22T10:00:00Z",
		Location:    "claude-desktop",
		Tags:        []string{"production", "research"},
	}

	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	agent := loaded.Agents["test-agent"]
	if agent.Description != "A test agent" {
		t.Errorf("description = %q, want 'A test agent'", agent.Description)
	}
	if agent.CreatedBy != "dashboard" {
		t.Errorf("created_by = %q, want 'dashboard'", agent.CreatedBy)
	}
	if agent.Location != "claude-desktop" {
		t.Errorf("location = %q, want 'claude-desktop'", agent.Location)
	}
	if len(agent.Tags) != 2 || agent.Tags[0] != "production" {
		t.Errorf("tags = %v, want [production research]", agent.Tags)
	}
}

func TestQuarantineConfigDefaults(t *testing.T) {
	cfg := Defaults()
	if !cfg.Quarantine.Enabled {
		t.Error("quarantine should be enabled by default")
	}
	if cfg.Quarantine.ExpiryHours != 24 {
		t.Errorf("expiry_hours = %d, want 24", cfg.Quarantine.ExpiryHours)
	}
}

func TestQuarantineConfigLoad(t *testing.T) {
	content := `
version: "1"
server:
  port: 8080
quarantine:
  enabled: false
  expiry_hours: 48
`
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Quarantine.Enabled {
		t.Error("quarantine should be disabled")
	}
	if cfg.Quarantine.ExpiryHours != 48 {
		t.Errorf("expiry_hours = %d, want 48", cfg.Quarantine.ExpiryHours)
	}
}

func TestAgentBackwardCompatible(t *testing.T) {
	// Old-format YAML with only can_message should still work
	content := `
version: "1"
server:
  port: 8080
agents:
  legacy-agent:
    can_message: [other-agent]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	agent := cfg.Agents["legacy-agent"]
	if len(agent.CanMessage) != 1 || agent.CanMessage[0] != "other-agent" {
		t.Errorf("can_message = %v, want [other-agent]", agent.CanMessage)
	}
	// New fields should be zero values
	if agent.Description != "" {
		t.Error("description should be empty for legacy config")
	}
}
