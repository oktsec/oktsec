package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// RuleGenerator converts LLM findings into Aguara YAML rules.
type RuleGenerator struct {
	outputDir       string
	requireApproval bool
	minConfidence   float64
	counter         atomic.Int64
	onGenerated     func(GeneratedRule) // callback for dashboard/audit
}

// GeneratedRule is a rule created by the LLM.
type GeneratedRule struct {
	ID          string        `yaml:"id" json:"id"`
	Name        string        `yaml:"name" json:"name"`
	Description string        `yaml:"description" json:"description"`
	Severity    string        `yaml:"severity" json:"severity"`
	Category    string        `yaml:"category" json:"category"`
	Source      string        `yaml:"source" json:"source"`
	GeneratedBy string        `yaml:"generated_by" json:"generated_by"`
	MessageID   string        `yaml:"generated_from" json:"generated_from"`
	Confidence  float64       `yaml:"confidence" json:"confidence"`
	Status      string        `yaml:"status" json:"status"` // pending_review, active, rejected
	Patterns    []RulePattern `yaml:"patterns" json:"patterns"`
	Examples    RuleExamples  `yaml:"examples,omitempty" json:"examples,omitempty"`
}

// RulePattern is a detection pattern in the generated rule.
type RulePattern struct {
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}

// RuleExamples holds true/false positive examples.
type RuleExamples struct {
	TruePositive  []string `yaml:"true_positive,omitempty" json:"true_positive,omitempty"`
	FalsePositive []string `yaml:"false_positive,omitempty" json:"false_positive,omitempty"`
}

// NewRuleGenerator creates a rule generator.
func NewRuleGenerator(outputDir string, requireApproval bool, minConfidence float64) *RuleGenerator {
	if minConfidence <= 0 {
		minConfidence = 0.8
	}
	return &RuleGenerator{
		outputDir:       outputDir,
		requireApproval: requireApproval,
		minConfidence:   minConfidence,
	}
}

// OnGenerated sets a callback invoked when a new rule is generated.
func (g *RuleGenerator) OnGenerated(fn func(GeneratedRule)) {
	g.onGenerated = fn
}

// Generate creates a YAML rule from an LLM threat finding.
// Returns nil if the LLM didn't suggest a rule, confidence is below threshold,
// or the suggested pattern is invalid regex.
func (g *RuleGenerator) Generate(threat ThreatFinding, provider, messageID string) (*GeneratedRule, error) {
	if threat.Suggestion == nil {
		return nil, nil
	}

	if threat.Confidence < g.minConfidence {
		return nil, nil
	}

	// Validate the regex pattern
	if _, err := regexp.Compile(threat.Suggestion.Pattern); err != nil {
		return nil, fmt.Errorf("invalid regex from LLM %q: %w", threat.Suggestion.Pattern, err)
	}

	id := fmt.Sprintf("LLM-%03d", g.counter.Add(1))

	status := "active"
	if g.requireApproval {
		status = "pending_review"
	}

	rule := &GeneratedRule{
		ID:          id,
		Name:        threat.Suggestion.Name,
		Description: threat.Description,
		Severity:    threat.Suggestion.Severity,
		Category:    threat.Suggestion.Category,
		Source:      "llm-generated",
		GeneratedBy: provider,
		MessageID:   messageID,
		Confidence:  threat.Confidence,
		Status:      status,
		Patterns: []RulePattern{
			{Type: "regex", Value: threat.Suggestion.Pattern},
		},
	}

	if err := g.writeRule(rule); err != nil {
		return nil, fmt.Errorf("write rule: %w", err)
	}

	llmRulesGenerated.Inc()

	if g.onGenerated != nil {
		g.onGenerated(*rule)
	}

	return rule, nil
}

func (g *RuleGenerator) writeRule(rule *GeneratedRule) error {
	if err := os.MkdirAll(g.outputDir, 0o755); err != nil {
		return err
	}

	data, err := yaml.Marshal(rule)
	if err != nil {
		return err
	}

	filename := strings.ToLower(rule.ID) + ".yaml"
	return os.WriteFile(filepath.Join(g.outputDir, filename), data, 0o644)
}

// ApproveRule changes a pending rule to active.
func (g *RuleGenerator) ApproveRule(ruleID string) error {
	return g.setRuleStatus(ruleID, "active")
}

// RejectRule marks a rule as rejected.
func (g *RuleGenerator) RejectRule(ruleID string) error {
	return g.setRuleStatus(ruleID, "rejected")
}

// DeactivateRule disables an active rule without deleting it.
func (g *RuleGenerator) DeactivateRule(ruleID string) error {
	return g.setRuleStatus(ruleID, "disabled")
}

func (g *RuleGenerator) setRuleStatus(ruleID, status string) error {
	filename := strings.ToLower(ruleID) + ".yaml"
	path := filepath.Join(g.outputDir, filename)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rule %s: %w", ruleID, err)
	}

	var rule GeneratedRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return fmt.Errorf("parse rule %s: %w", ruleID, err)
	}

	rule.Status = status
	newData, err := yaml.Marshal(&rule)
	if err != nil {
		return err
	}

	return os.WriteFile(path, newData, 0o644)
}

// ListPending returns all rules with status pending_review.
func (g *RuleGenerator) ListPending() ([]GeneratedRule, error) {
	return g.listByStatus("pending_review")
}

// ListActive returns all approved LLM-generated rules.
func (g *RuleGenerator) ListActive() ([]GeneratedRule, error) {
	return g.listByStatus("active")
}

// ListDisabled returns all disabled LLM-generated rules.
func (g *RuleGenerator) ListDisabled() ([]GeneratedRule, error) {
	return g.listByStatus("disabled")
}

func (g *RuleGenerator) listByStatus(status string) ([]GeneratedRule, error) {
	entries, err := os.ReadDir(g.outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var rules []GeneratedRule
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(g.outputDir, e.Name()))
		if err != nil {
			continue
		}

		var rule GeneratedRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			continue
		}
		if rule.Status == status {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}
