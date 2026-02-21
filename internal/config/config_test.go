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
