package config

// IntegrationPreset defines allowed domains for a known service integration.
type IntegrationPreset struct {
	Name        string
	Description string
	Domains     []string
}

// IntegrationPresets maps preset names to their domain allowlists.
// Used by egress policy: agents with `integrations: ["slack"]` automatically
// get Slack domains in their allowed egress list.
var IntegrationPresets = map[string]IntegrationPreset{
	"slack": {
		Name:        "Slack",
		Description: "Slack API, webhooks, and OAuth",
		Domains:     []string{"slack.com", "api.slack.com", "hooks.slack.com", "files.slack.com"},
	},
	"github": {
		Name:        "GitHub",
		Description: "GitHub API, raw content, and OAuth",
		Domains:     []string{"github.com", "api.github.com", "raw.githubusercontent.com"},
	},
	"telegram": {
		Name:        "Telegram",
		Description: "Telegram Bot API",
		Domains:     []string{"api.telegram.org"},
	},
	"discord": {
		Name:        "Discord",
		Description: "Discord API and CDN",
		Domains:     []string{"discord.com", "discordapp.com", "cdn.discordapp.com"},
	},
	"jira": {
		Name:        "Jira/Atlassian",
		Description: "Atlassian Jira and Confluence APIs",
		Domains:     []string{"*.atlassian.net", "*.jira.com"},
	},
	"linear": {
		Name:        "Linear",
		Description: "Linear project management API",
		Domains:     []string{"api.linear.app", "linear.app"},
	},
	"notion": {
		Name:        "Notion",
		Description: "Notion API",
		Domains:     []string{"api.notion.com"},
	},
	"stripe": {
		Name:        "Stripe",
		Description: "Stripe payments API and webhooks",
		Domains:     []string{"api.stripe.com", "hooks.stripe.com"},
	},
	"openai": {
		Name:        "OpenAI",
		Description: "OpenAI API",
		Domains:     []string{"api.openai.com"},
	},
	"anthropic": {
		Name:        "Anthropic",
		Description: "Anthropic Claude API",
		Domains:     []string{"api.anthropic.com"},
	},
	"supabase": {
		Name:        "Supabase",
		Description: "Supabase API and realtime",
		Domains:     []string{"*.supabase.co", "*.supabase.in"},
	},
	"firebase": {
		Name:        "Firebase",
		Description: "Firebase and Google Cloud APIs",
		Domains:     []string{"*.firebaseio.com", "*.googleapis.com", "*.firebaseapp.com"},
	},
	"npm": {
		Name:        "npm",
		Description: "npm registry",
		Domains:     []string{"registry.npmjs.org"},
	},
	"pypi": {
		Name:        "PyPI",
		Description: "Python Package Index",
		Domains:     []string{"pypi.org", "files.pythonhosted.org"},
	},
	"docker": {
		Name:        "Docker",
		Description: "Docker Hub and registry",
		Domains:     []string{"registry-1.docker.io", "auth.docker.io", "hub.docker.com"},
	},
	"huggingface": {
		Name:        "Hugging Face",
		Description: "Hugging Face models and datasets",
		Domains:     []string{"huggingface.co", "*.hf.co"},
	},
}

// ResolveIntegrationDomains returns all domains for the given integration preset names.
func ResolveIntegrationDomains(names []string) []string {
	var domains []string
	seen := make(map[string]bool)
	for _, name := range names {
		preset, ok := IntegrationPresets[name]
		if !ok {
			continue
		}
		for _, d := range preset.Domains {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	return domains
}
