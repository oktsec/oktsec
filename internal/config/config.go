// Package config loads and validates the oktsec YAML configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/safefile"
	"gopkg.in/yaml.v3"
)

// Config is the top-level oktsec configuration.
type Config struct {
	Version        string                         `yaml:"version"`
	Server         ServerConfig                   `yaml:"server"`
	Identity       IdentityConfig                 `yaml:"identity"`
	DefaultPolicy  string                         `yaml:"default_policy,omitempty"` // "allow" (default) or "deny"
	Agents         map[string]Agent               `yaml:"agents"`
	Rules          []RuleAction                   `yaml:"rules"`
	Webhooks         []Webhook                      `yaml:"webhooks"`
	CategoryWebhooks []CategoryWebhook              `yaml:"category_webhooks,omitempty"`
	DBBackend        string                         `yaml:"db_backend,omitempty"`  // "sqlite" (default) or "postgres"
	DBPath           string                         `yaml:"db_path,omitempty"`     // SQLite file path
	DBDSN            string                         `yaml:"db_dsn,omitempty"`      // PostgreSQL connection string
	CustomRulesDir string                         `yaml:"custom_rules_dir,omitempty"`
	Quarantine     QuarantineConfig               `yaml:"quarantine,omitempty"`
	RateLimit      RateLimitConfig                `yaml:"rate_limit,omitempty"`
	Anomaly        AnomalyConfig                  `yaml:"anomaly,omitempty"`
	ForwardProxy   ForwardProxyConfig             `yaml:"forward_proxy,omitempty"`
	Alerting       AlertingConfig                 `yaml:"alerting,omitempty"`
	Gateway        GatewayConfig                  `yaml:"gateway,omitempty"`
	MCPServers     map[string]MCPServerConfig     `yaml:"mcp_servers,omitempty"`
	LLM            LLMConfig                      `yaml:"llm,omitempty"`
	Telemetry      TelemetryConfig                `yaml:"telemetry,omitempty"`
}

// TelemetryConfig controls the anonymous usage ping.
type TelemetryConfig struct {
	Disabled bool `yaml:"disabled,omitempty"` // set true to opt out of anonymous pings
}

// LLMConfig configures the async LLM analysis layer.
// The user selects their own provider: commercial APIs (OpenAI, Claude)
// or local open-source models (Ollama, vLLM, llama.cpp, LM Studio).
type LLMConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Provider      string `yaml:"provider"`                // openai | claude | webhook
	Model         string `yaml:"model"`                   // model name/ID
	BaseURL       string `yaml:"base_url,omitempty"`      // override for Ollama, vLLM, Azure, etc.
	APIKey        string `yaml:"api_key,omitempty"`       // direct API key (takes precedence)
	APIKeyEnv     string `yaml:"api_key_env,omitempty"`   // env var name
	APIVersion    string `yaml:"api_version,omitempty"`   // for Azure OpenAI

	MaxTokens     int     `yaml:"max_tokens,omitempty"`     // per-analysis (default: 2048)
	Temperature   float64 `yaml:"temperature,omitempty"`    // low = more deterministic (default: 0.1)
	MaxConcurrent int     `yaml:"max_concurrent,omitempty"` // analysis workers (default: 3)
	QueueSize     int     `yaml:"queue_size,omitempty"`     // buffer before drop (default: 100)
	MaxDailyReqs  int64   `yaml:"max_daily_requests,omitempty"` // 0 = unlimited
	Timeout       string  `yaml:"timeout,omitempty"`        // duration string (default: "30s")

	Analyze          LLMAnalyzeConfig  `yaml:"analyze,omitempty"`
	Triage           LLMTriageConfig   `yaml:"triage,omitempty"`
	MinContentLength int              `yaml:"min_content_length,omitempty"` // skip short messages

	Budget     LLMBudgetConfig     `yaml:"budget,omitempty"`
	Fallback   LLMFallbackConfig   `yaml:"fallback,omitempty"`
	RuleGen    LLMRuleGenConfig    `yaml:"rulegen,omitempty"`
	Intent     LLMIntentConfig     `yaml:"intent,omitempty"`
	Webhook    LLMWebhookConfig    `yaml:"webhook,omitempty"`
	Escalation LLMEscalationConfig `yaml:"escalation,omitempty"`
}

// LLMEscalationConfig controls automatic verdict escalation driven by LLM
// threat analysis. When the LLM detects a high-risk threat for an agent,
// all future verdicts for that agent are escalated one level for a TTL window.
type LLMEscalationConfig struct {
	Enabled       bool    `yaml:"enabled"`
	RiskThreshold float64 `yaml:"risk_threshold,omitempty"` // min risk score to trigger (default: 80)
	TTLMinutes    int     `yaml:"ttl_minutes,omitempty"`    // escalation duration (default: 30)
}

// LLMFallbackConfig configures a secondary LLM provider used when the
// primary fails. Supports the same provider types as the primary.
type LLMFallbackConfig struct {
	Provider   string `yaml:"provider,omitempty"`      // openai | claude | webhook
	Model      string `yaml:"model,omitempty"`
	BaseURL    string `yaml:"base_url,omitempty"`
	APIKey     string `yaml:"api_key,omitempty"`
	APIKeyEnv  string `yaml:"api_key_env,omitempty"`
	APIVersion string `yaml:"api_version,omitempty"`
	MaxTokens  int    `yaml:"max_tokens,omitempty"`
	Timeout    string `yaml:"timeout,omitempty"`
}

// LLMAnalyzeConfig controls which verdict types trigger LLM analysis.
type LLMAnalyzeConfig struct {
	Clean       bool `yaml:"clean"`
	Flagged     bool `yaml:"flagged"`
	Quarantined bool `yaml:"quarantined"`
	Blocked     bool `yaml:"blocked"`
}

// LLMTriageConfig controls the signal detector pre-filter.
type LLMTriageConfig struct {
	Enabled           bool     `yaml:"enabled"`
	SkipVerdicts      []string `yaml:"skip_verdicts,omitempty"`
	SensitiveKeywords []string `yaml:"sensitive_keywords,omitempty"`
	MinContentLength  int      `yaml:"min_content_length,omitempty"`
	NewAgentPairs     bool     `yaml:"new_agent_pairs,omitempty"`
	SampleRate        float64  `yaml:"sample_rate,omitempty"`
	ExternalURLs      bool     `yaml:"external_urls,omitempty"`
}

// LLMBudgetConfig controls LLM spending limits to prevent billing surprises.
type LLMBudgetConfig struct {
	DailyLimitUSD   float64 `yaml:"daily_limit_usd,omitempty"`   // hard cap per day (0 = unlimited)
	MonthlyLimitUSD float64 `yaml:"monthly_limit_usd,omitempty"` // hard cap per month (0 = unlimited)
	WarnThreshold   float64 `yaml:"warn_threshold,omitempty"`    // alert at this fraction of limit (default: 0.8)
	OnLimit         string  `yaml:"on_limit,omitempty"`          // "skip" (default) | "block"
}

// LLMRuleGenConfig controls automatic rule generation from LLM findings.
type LLMRuleGenConfig struct {
	Enabled         bool    `yaml:"enabled"`
	OutputDir       string  `yaml:"output_dir,omitempty"`
	AutoReload      bool    `yaml:"auto_reload"`
	RequireApproval bool    `yaml:"require_approval"`
	MinConfidence   float64 `yaml:"min_confidence,omitempty"`
}

// LLMIntentConfig controls LLM-enhanced intent analysis.
type LLMIntentConfig struct {
	Enhanced      bool `yaml:"enhanced"`
	HistoryWindow int  `yaml:"history_window,omitempty"`
}

// LLMWebhookConfig holds settings for the custom webhook LLM provider.
type LLMWebhookConfig struct {
	URL     string            `yaml:"url,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

// ServerConfig holds proxy server settings.
type ServerConfig struct {
	Port          int    `yaml:"port"`
	Bind          string `yaml:"bind"`           // Address to bind (default: 127.0.0.1)
	LogLevel      string `yaml:"log_level"`
	RequireIntent bool   `yaml:"require_intent"`                        // Require agents to declare intent in messages
	APIKey        string `yaml:"api_key,omitempty" json:"api_key,omitempty"` // API key for /v1/* and /metrics endpoints (empty = no auth)
}

// IdentityConfig configures agent identity verification.
type IdentityConfig struct {
	KeysDir          string          `yaml:"keys_dir"`
	RequireSignature bool            `yaml:"require_signature"`
	Ephemeral        EphemeralConfig `yaml:"ephemeral,omitempty"`
}

// EphemeralConfig controls task-scoped ephemeral key issuance.
type EphemeralConfig struct {
	Enabled    bool   `yaml:"enabled"`
	MaxTTL     string `yaml:"max_ttl,omitempty"`      // duration string, default "4h"
	MaxPerTask int    `yaml:"max_per_task,omitempty"`  // default 10
}

// Agent defines per-agent access control and metadata.
type Agent struct {
	CanMessage      []string                `yaml:"can_message"`
	BlockedContent  []string                `yaml:"blocked_content"`
	AllowedTools    []string                `yaml:"allowed_tools,omitempty"`    // tool names the agent can call (empty = all)
	ToolPolicies    map[string]ToolPolicy   `yaml:"tool_policies,omitempty"`   // per-tool enforcement policies
	ToolConstraints []ToolConstraintConfig  `yaml:"tool_constraints,omitempty"` // per-tool parameter constraints
	ToolChainRules  []ToolChainRuleConfig   `yaml:"tool_chain_rules,omitempty"` // sequential tool blocking rules
	ScanProfile     string                  `yaml:"scan_profile,omitempty"`     // strict (default), content-aware, minimal
	Suspended       bool                    `yaml:"suspended,omitempty"`
	Description     string                  `yaml:"description,omitempty"`
	CreatedBy       string                  `yaml:"created_by,omitempty"`
	CreatedAt       string                  `yaml:"created_at,omitempty"`
	Location        string                  `yaml:"location,omitempty"`
	Tags            []string                `yaml:"tags,omitempty"`
	Egress          *EgressPolicy           `yaml:"egress,omitempty"`
}

// ToolConstraintConfig defines per-tool parameter and usage limits.
type ToolConstraintConfig struct {
	Tool             string                          `yaml:"tool" json:"tool"`
	Parameters       map[string]ParamConstraintConfig `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	MaxResponseBytes int                             `yaml:"max_response_bytes,omitempty" json:"max_response_bytes,omitempty"`
	CooldownSecs     int                             `yaml:"cooldown_secs,omitempty" json:"cooldown_secs,omitempty"`
}

// ParamConstraintConfig defines validation rules for a single tool parameter.
type ParamConstraintConfig struct {
	AllowedPatterns []string `yaml:"allowed_patterns,omitempty" json:"allowed_patterns,omitempty"` // glob patterns
	BlockedPatterns []string `yaml:"blocked_patterns,omitempty" json:"blocked_patterns,omitempty"` // glob patterns
	MaxLength       int      `yaml:"max_length,omitempty" json:"max_length,omitempty"`
}

// ToolChainRuleConfig blocks certain tools after a triggering tool is called.
type ToolChainRuleConfig struct {
	If           string   `yaml:"if" json:"if"`                       // tool that triggers
	Then         []string `yaml:"then" json:"then"`                   // tools that become blocked
	CooldownSecs int      `yaml:"cooldown_secs" json:"cooldown_secs"` // how long the block lasts
}

// ToolPolicy defines per-tool enforcement rules for an agent.
type ToolPolicy struct {
	MaxAmount            float64 `yaml:"max_amount,omitempty"`             // max value per call (e.g. spending limit)
	DailyLimit           float64 `yaml:"daily_limit,omitempty"`            // cumulative daily limit
	RequireApprovalAbove float64 `yaml:"require_approval_above,omitempty"` // quarantine if value exceeds threshold
	RateLimit            int     `yaml:"rate_limit,omitempty"`             // max calls per hour
}

// EgressPolicy defines per-agent outbound traffic controls.
// Nil means fall back to global forward_proxy settings.
type EgressPolicy struct {
	AllowedDomains    []string            `yaml:"allowed_domains,omitempty"`
	BlockedDomains    []string            `yaml:"blocked_domains,omitempty"`
	ToolRestrictions  map[string][]string `yaml:"tool_restrictions,omitempty"` // tool -> allowed domains (empty = no egress for that tool)
	ScanRequests      *bool               `yaml:"scan_requests,omitempty"`
	ScanResponses     *bool               `yaml:"scan_responses,omitempty"`
	BlockedCategories []string            `yaml:"blocked_categories,omitempty"`
	RateLimit         int                 `yaml:"rate_limit,omitempty"`
	RateWindow        int                 `yaml:"rate_window,omitempty"` // seconds (default: 60)
	Integrations      []string            `yaml:"integrations,omitempty"` // preset names: "slack", "github", "telegram", etc.
}

// QuarantineConfig configures the quarantine queue behavior.
type QuarantineConfig struct {
	Enabled       bool `yaml:"enabled"`
	ExpiryHours   int  `yaml:"expiry_hours"`
	RetentionDays int  `yaml:"retention_days"` // auto-purge audit entries older than N days (0 = keep forever)
}

// RuleAction maps a rule ID to an enforcement action.
type RuleAction struct {
	ID           string   `yaml:"id"`
	Severity     string   `yaml:"severity"`
	Action       string   `yaml:"action"` // block, quarantine, allow-and-flag
	Notify       []string `yaml:"notify"`
	Template     string   `yaml:"template,omitempty"`       // webhook body template with {{RULE}}, {{ACTION}}, etc.
	ApplyToTools []string `yaml:"apply_to_tools,omitempty"` // rule only enforced for these tools (empty = all)
	ExemptTools  []string `yaml:"exempt_tools,omitempty"`   // rule NOT enforced for these tools
}

// ScanProfile constants.
const (
	ScanProfileStrict       = "strict"
	ScanProfileContentAware = "content-aware"
	ScanProfileMinimal      = "minimal"
)

// ContentTools are tools that handle file content (not execution).
// Their arguments contain file content, search queries, prompts, etc.
// Agent is included because its arguments are sub-agent prompts that
// may contain code examples, URLs, or command patterns as documentation,
// not as executable actions. The actual execution is scanned strictly
// when the sub-agent calls Bash/Write/etc.
var ContentTools = map[string]bool{
	"Edit": true, "Write": true, "MultiEdit": true,
	"Read": true, "Glob": true, "Grep": true, "NotebookEdit": true,
	"Agent": true,
}

// DevWorkflowTools are tools used for developer workflow where arguments
// contain descriptive text (commit messages, task descriptions, prompts).
// NLP rules are exempt on these because the text is authored content.
var DevWorkflowTools = map[string]bool{
	"Agent": true, "TaskCreate": true, "TaskUpdate": true, "TaskOutput": true,
}

// MinimalEnforceRules are the only rules enforced in minimal profile.
var MinimalEnforceRules = map[string]bool{
	"TC-001": true, // Path traversal
	"TC-003": true, // System directory write
	"TC-006": true, // Credential in tool args
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

// AlertingConfig controls alert notification behavior.
type AlertingConfig struct {
	Cooldown    string `yaml:"cooldown,omitempty"`     // min interval between duplicate alerts (default: "5m")
	LLMThreats bool   `yaml:"llm_threats,omitempty"`   // alert on LLM-detected threats
	Anomalies  bool   `yaml:"anomalies,omitempty"`     // alert on anomaly detection (default: true via anomaly config)
	Suspensions bool  `yaml:"suspensions,omitempty"`   // alert on agent auto-suspension
}

// ForwardProxyConfig configures the HTTP forward proxy for Docker Sandbox integration.
type ForwardProxyConfig struct {
	Enabled        bool     `yaml:"enabled"`                    // Default: false
	Port           int      `yaml:"port,omitempty"`             // Default: 8083
	Bind           string   `yaml:"bind,omitempty"`             // Default: 127.0.0.1
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`  // Empty = allow all
	BlockedDomains []string `yaml:"blocked_domains,omitempty"`  // Takes precedence over allowed
	ScanRequests   bool     `yaml:"scan_requests"`              // Scan outbound HTTP bodies (default: true)
	ScanResponses  bool     `yaml:"scan_responses"`             // Scan inbound HTTP bodies (default: false)
	MaxBodySize    int64    `yaml:"max_body_size,omitempty"`    // Max body to scan in bytes (default: 1MB)
}

// GatewayConfig configures the MCP gateway mode.
type GatewayConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Port          int    `yaml:"port"`            // default 9090
	Bind          string `yaml:"bind"`            // default 127.0.0.1
	EndpointPath  string `yaml:"endpoint_path"`   // default /mcp
	ScanResponses bool   `yaml:"scan_responses"`  // scan backend responses
}

// MCPServerConfig defines a backend MCP server to proxy through the gateway.
type MCPServerConfig struct {
	Transport string            `yaml:"transport"`         // "stdio" or "http"
	Command   string            `yaml:"command,omitempty"` // for stdio
	Args      []string          `yaml:"args,omitempty"`
	URL       string            `yaml:"url,omitempty"`     // for http
	Headers   map[string]string `yaml:"headers,omitempty"`
	Env       map[string]string `yaml:"env,omitempty"` // env vars for stdio
}

// CategoryWebhook binds a rule category to default notification channels.
type CategoryWebhook struct {
	Category string   `yaml:"category"`
	Notify   []string `yaml:"notify"`
}

// Webhook defines an outgoing notification endpoint.
type Webhook struct {
	Name   string   `yaml:"name,omitempty"` // friendly name for dashboard selection
	URL    string   `yaml:"url"`
	Events []string `yaml:"events"` // blocked, quarantined, rejected
}

// WebhookByName returns the first webhook with the given name, or nil.
func (c *Config) WebhookByName(name string) *Webhook {
	for i := range c.Webhooks {
		if c.Webhooks[i].Name == name {
			return &c.Webhooks[i]
		}
	}
	return nil
}

// Load reads and parses an oktsec config file.
// The file must not be a symlink and must not exceed 1 MB.
func Load(path string) (*Config, error) {
	data, err := safefile.ReadFileMax(path, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// Apply config migrations for backward compatibility.
	data, _, migrateErr := MigrateConfig(data)
	if migrateErr != nil {
		return nil, fmt.Errorf("migrating config: %w", migrateErr)
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
			Enabled:       true,
			ExpiryHours:   24,
			RetentionDays: 90,
		},
		RateLimit: RateLimitConfig{
			PerAgent: 100,
			WindowS:  60,
		},
		Anomaly: AnomalyConfig{
			CheckIntervalS: 60,
			RiskThreshold:  80,
			MinMessages:    10,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply zero-value defaults after unmarshal.
	// These ensure sensible behavior even when fields are omitted from YAML.
	if cfg.Quarantine.ExpiryHours == 0 {
		cfg.Quarantine.ExpiryHours = 24
	}
	if cfg.RateLimit.WindowS == 0 {
		cfg.RateLimit.WindowS = 60
	}
	if cfg.Quarantine.RetentionDays == 0 {
		cfg.Quarantine.RetentionDays = 90
	}
	if cfg.Anomaly.CheckIntervalS == 0 {
		cfg.Anomaly.CheckIntervalS = 60
	}

	// Default and resolve db_path to absolute
	if cfg.DBPath == "" {
		cfg.DBPath = "oktsec.db"
	}
	if cfg.DBPath != ":memory:" {
		abs, err := filepath.Abs(cfg.DBPath)
		if err != nil {
			return nil, fmt.Errorf("resolving db_path: %w", err)
		}
		cfg.DBPath = abs
	}

	// Forward proxy defaults
	if cfg.ForwardProxy.Port == 0 {
		cfg.ForwardProxy.Port = 8083
	}

	// Gateway defaults
	if cfg.Gateway.Port == 0 {
		cfg.Gateway.Port = 9090
	}
	if cfg.Gateway.EndpointPath == "" {
		cfg.Gateway.EndpointPath = "/mcp"
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
			KeysDir:          DefaultKeysDir(),
			RequireSignature: true,
		},
		Agents: make(map[string]Agent),
		Quarantine: QuarantineConfig{
			Enabled:       true,
			ExpiryHours:   24,
			RetentionDays: 90,
		},
		RateLimit: RateLimitConfig{
			PerAgent: 100,
			WindowS:  60,
		},
		Anomaly: AnomalyConfig{
			CheckIntervalS: 60,
			RiskThreshold:  80,
			MinMessages:    10,
		},
	}
}

// Save writes the config to a YAML file at the given path.
// Creates a .bak backup of the existing file before overwriting.
func (c *Config) Save(path string) error {
	// Backup existing file (best-effort)
	if existing, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", existing, 0o600)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
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
		switch agent.ScanProfile {
		case "", ScanProfileStrict, ScanProfileContentAware, ScanProfileMinimal:
			// valid
		default:
			return fmt.Errorf("agent %q has invalid scan_profile %q (valid: strict, content-aware, minimal)", name, agent.ScanProfile)
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
			return fmt.Errorf("rule %q has invalid action %q (valid: block, quarantine, allow-and-flag, ignore)", ra.ID, ra.Action)
		}
		if len(ra.ApplyToTools) > 0 && len(ra.ExemptTools) > 0 {
			return fmt.Errorf("rule %q cannot have both apply_to_tools and exempt_tools", ra.ID)
		}
	}
	// Gateway validation (transport checks only; backend count and port
	// binding are validated at gateway startup so `serve` can manage it
	// via the dashboard).
	if c.Gateway.Enabled && len(c.MCPServers) > 0 {
		if c.Gateway.Port < 1 || c.Gateway.Port > 65535 {
			return fmt.Errorf("invalid gateway port: %d", c.Gateway.Port)
		}
		for name, srv := range c.MCPServers {
			switch srv.Transport {
			case "stdio":
				if srv.Command == "" {
					return fmt.Errorf("mcp_server %q: stdio transport requires command", name)
				}
			case "http":
				if srv.URL == "" {
					return fmt.Errorf("mcp_server %q: http transport requires url", name)
				}
			default:
				return fmt.Errorf("mcp_server %q: invalid transport %q (must be stdio or http)", name, srv.Transport)
			}
		}
	}
	// Forward proxy without domain lists is valid when scan_requests or scan_responses is enabled
	// (dual-layer mode: scanning without domain restriction)
	if c.ForwardProxy.Enabled && len(c.ForwardProxy.BlockedDomains) == 0 && len(c.ForwardProxy.AllowedDomains) == 0 &&
		!c.ForwardProxy.ScanRequests && !c.ForwardProxy.ScanResponses {
		return fmt.Errorf("forward_proxy is enabled without allowed_domains, blocked_domains, or scanning; configure at least one")
	}
	if c.ForwardProxy.MaxBodySize < 0 {
		return fmt.Errorf("forward_proxy.max_body_size must be non-negative")
	}
	// LLM config validation
	if c.LLM.Enabled {
		switch c.LLM.Provider {
		case "openai", "claude", "webhook":
			// valid
		default:
			return fmt.Errorf("llm.provider %q is invalid (must be openai, claude, or webhook)", c.LLM.Provider)
		}
		if c.LLM.Provider == "claude" && c.LLM.APIKey == "" && c.LLM.APIKeyEnv == "" {
			return fmt.Errorf("llm.api_key or llm.api_key_env is required for claude provider")
		}
		if c.LLM.Provider == "webhook" && c.LLM.Webhook.URL == "" {
			return fmt.Errorf("llm.webhook.url is required for webhook provider")
		}
		if (c.LLM.Provider == "openai" || c.LLM.Provider == "claude") && c.LLM.Model == "" {
			return fmt.Errorf("llm.model is required for %s provider", c.LLM.Provider)
		}
		if c.LLM.MaxTokens < 0 {
			return fmt.Errorf("llm.max_tokens must be > 0 when set")
		}
		if c.LLM.Temperature < 0 || c.LLM.Temperature > 2.0 {
			return fmt.Errorf("llm.temperature must be between 0 and 2.0")
		}
		if c.LLM.MaxConcurrent < 0 {
			return fmt.Errorf("llm.max_concurrent must be > 0 when set")
		}
		if c.LLM.QueueSize < 0 {
			return fmt.Errorf("llm.queue_size must be > 0 when set")
		}
		if c.LLM.MaxDailyReqs < 0 {
			return fmt.Errorf("llm.max_daily_requests must be > 0 when set")
		}
		if c.LLM.RuleGen.Enabled && c.LLM.RuleGen.OutputDir == "" {
			return fmt.Errorf("llm.rulegen.output_dir is required when rulegen is enabled")
		}
	}
	return nil
}
