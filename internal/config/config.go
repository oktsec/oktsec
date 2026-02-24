package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level oktsec configuration.
type Config struct {
	Version        string             `yaml:"version"`
	Server         ServerConfig       `yaml:"server"`
	Identity       IdentityConfig     `yaml:"identity"`
	DefaultPolicy  string             `yaml:"default_policy,omitempty"` // "allow" (default) or "deny"
	Agents         map[string]Agent   `yaml:"agents"`
	Rules          []RuleAction       `yaml:"rules"`
	Webhooks       []Webhook          `yaml:"webhooks"`
	CustomRulesDir string             `yaml:"custom_rules_dir,omitempty"`
	Quarantine     QuarantineConfig   `yaml:"quarantine,omitempty"`
	RateLimit      RateLimitConfig    `yaml:"rate_limit,omitempty"`
	Anomaly        AnomalyConfig      `yaml:"anomaly,omitempty"`
	ForwardProxy   ForwardProxyConfig `yaml:"forward_proxy,omitempty"`
}

// ServerConfig holds proxy server settings.
type ServerConfig struct {
	Port     int    `yaml:"port"`
	Bind     string `yaml:"bind"` // Address to bind (default: 127.0.0.1)
	LogLevel string `yaml:"log_level"`
}

// IdentityConfig configures agent identity verification.
type IdentityConfig struct {
	KeysDir          string `yaml:"keys_dir"`
	RequireSignature bool   `yaml:"require_signature"`
}

// Agent defines per-agent access control and metadata.
type Agent struct {
	CanMessage     []string `yaml:"can_message"`
	BlockedContent []string `yaml:"blocked_content"`
	AllowedTools   []string `yaml:"allowed_tools,omitempty"` // tool names the agent can call (empty = all)
	Suspended      bool     `yaml:"suspended,omitempty"`
	Description    string   `yaml:"description,omitempty"`
	CreatedBy      string   `yaml:"created_by,omitempty"`
	CreatedAt      string   `yaml:"created_at,omitempty"`
	Location       string   `yaml:"location,omitempty"`
	Tags           []string `yaml:"tags,omitempty"`
}

// QuarantineConfig configures the quarantine queue behavior.
type QuarantineConfig struct {
	Enabled       bool `yaml:"enabled"`
	ExpiryHours   int  `yaml:"expiry_hours"`
	RetentionDays int  `yaml:"retention_days"` // auto-purge audit entries older than N days (0 = keep forever)
}

// RuleAction maps a rule ID to an enforcement action.
type RuleAction struct {
	ID       string   `yaml:"id"`
	Severity string   `yaml:"severity"`
	Action   string   `yaml:"action"` // block, quarantine, allow-and-flag
	Notify   []string `yaml:"notify"`
	Template string   `yaml:"template,omitempty"` // webhook body template with {{RULE}}, {{ACTION}}, etc.
}

// RateLimitConfig controls per-agent message rate limiting.
type RateLimitConfig struct {
	PerAgent int `yaml:"per_agent"` // max messages per window (0 = disabled)
	WindowS  int `yaml:"window"`    // window size in seconds (default: 60)
}

// AnomalyConfig controls automatic risk-based alerting and suspension.
type AnomalyConfig struct {
	CheckIntervalS int     `yaml:"check_interval"` // seconds between checks (default: 60)
	RiskThreshold  float64 `yaml:"risk_threshold"` // risk score to trigger alert (0-100)
	MinMessages    int     `yaml:"min_messages"`   // min messages before evaluating risk
	AutoSuspend    bool    `yaml:"auto_suspend"`   // suspend agent when threshold exceeded
}

// ForwardProxyConfig configures the HTTP forward proxy for Docker Sandbox integration.
type ForwardProxyConfig struct {
	Enabled        bool     `yaml:"enabled"`                    // Default: false
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`  // Empty = allow all
	BlockedDomains []string `yaml:"blocked_domains,omitempty"`  // Takes precedence over allowed
	ScanRequests   bool     `yaml:"scan_requests"`              // Scan outbound HTTP bodies (default: true)
	ScanResponses  bool     `yaml:"scan_responses"`             // Scan inbound HTTP bodies (default: false)
	MaxBodySize    int64    `yaml:"max_body_size,omitempty"`    // Max body to scan in bytes (default: 1MB)
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
		Quarantine: QuarantineConfig{
			Enabled:     true,
			ExpiryHours: 24,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply zero-value defaults after unmarshal
	if cfg.Quarantine.ExpiryHours == 0 {
		cfg.Quarantine.ExpiryHours = 24
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
		Quarantine: QuarantineConfig{
			Enabled:     true,
			ExpiryHours: 24,
		},
	}
}

// Save writes the config to a YAML file at the given path.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// Validate checks that the config is consistent.
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Server.Port)
	}
	if c.Identity.RequireSignature && c.Identity.KeysDir == "" {
		return fmt.Errorf("keys_dir is required when require_signature is true")
	}
	switch c.DefaultPolicy {
	case "", "allow", "deny":
		// valid
	default:
		return fmt.Errorf("invalid default_policy %q (must be allow or deny)", c.DefaultPolicy)
	}
	for name, agent := range c.Agents {
		for _, target := range agent.CanMessage {
			if target == name {
				return fmt.Errorf("agent %q lists itself in can_message", name)
			}
		}
	}
	seen := make(map[string]bool, len(c.Rules))
	for _, ra := range c.Rules {
		if seen[ra.ID] {
			return fmt.Errorf("duplicate rule override for %q", ra.ID)
		}
		seen[ra.ID] = true
		switch ra.Action {
		case "block", "quarantine", "allow-and-flag", "ignore":
			// valid
		default:
			return fmt.Errorf("rule %q has invalid action %q", ra.ID, ra.Action)
		}
	}
	if c.ForwardProxy.Enabled && len(c.ForwardProxy.BlockedDomains) == 0 && len(c.ForwardProxy.AllowedDomains) == 0 {
		return fmt.Errorf("forward_proxy is enabled without allowed_domains or blocked_domains (open proxy); configure at least one")
	}
	if c.ForwardProxy.MaxBodySize < 0 {
		return fmt.Errorf("forward_proxy.max_body_size must be non-negative")
	}
	return nil
}
