package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level oktsec configuration.
type Config struct {
	Version  string          `yaml:"version"`
	Server   ServerConfig    `yaml:"server"`
	Identity IdentityConfig  `yaml:"identity"`
	Agents   map[string]Agent `yaml:"agents"`
	Rules    []RuleAction    `yaml:"rules"`
	Webhooks []Webhook       `yaml:"webhooks"`
}

// ServerConfig holds proxy server settings.
type ServerConfig struct {
	Port     int    `yaml:"port"`
	Bind     string `yaml:"bind"`      // Address to bind (default: 127.0.0.1)
	LogLevel string `yaml:"log_level"`
}

// IdentityConfig configures agent identity verification.
type IdentityConfig struct {
	KeysDir          string `yaml:"keys_dir"`
	RequireSignature bool   `yaml:"require_signature"`
}

// Agent defines per-agent access control.
type Agent struct {
	CanMessage     []string `yaml:"can_message"`
	BlockedContent []string `yaml:"blocked_content"`
}

// RuleAction maps a rule ID to an enforcement action.
type RuleAction struct {
	ID       string   `yaml:"id"`
	Severity string   `yaml:"severity"`
	Action   string   `yaml:"action"` // block, quarantine, allow-and-flag
	Notify   []string `yaml:"notify"`
}

// Webhook defines an outgoing notification endpoint.
type Webhook struct {
	URL    string   `yaml:"url"`
	Events []string `yaml:"events"` // blocked, quarantined, rejected
}

// Load reads and parses an oktsec config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &Config{
		Version: "1",
		Server: ServerConfig{
			Port:     8080,
			LogLevel: "info",
		},
		Identity: IdentityConfig{
			RequireSignature: true,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

// Defaults returns a config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Version: "1",
		Server: ServerConfig{
			Port:     8080,
			LogLevel: "info",
		},
		Identity: IdentityConfig{
			KeysDir:          "./keys",
			RequireSignature: true,
		},
		Agents: make(map[string]Agent),
	}
}

// Validate checks that the config is consistent.
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Server.Port)
	}
	if c.Identity.RequireSignature && c.Identity.KeysDir == "" {
		return fmt.Errorf("keys_dir is required when require_signature is true")
	}
	for name, agent := range c.Agents {
		for _, target := range agent.CanMessage {
			if target == name {
				return fmt.Errorf("agent %q lists itself in can_message", name)
			}
		}
	}
	for _, ra := range c.Rules {
		switch ra.Action {
		case "block", "quarantine", "allow-and-flag":
			// valid
		default:
			return fmt.Errorf("rule %q has invalid action %q", ra.ID, ra.Action)
		}
	}
	return nil
}
