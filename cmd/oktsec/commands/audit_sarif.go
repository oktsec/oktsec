package commands

import (
	"encoding/json"
	"fmt"
	"os"
)

// SARIF v2.1.0 types — minimal subset for audit output.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
	Properties       sarifProperties   `json:"properties,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifProperties struct {
	Product string `json:"product,omitempty"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func auditSeverityToSARIFLevel(s AuditSeverity) string {
	switch s {
	case AuditCritical, AuditHigh:
		return "error"
	case AuditMedium:
		return "warning"
	case AuditLow, AuditInfo:
		return "note"
	default:
		return "none"
	}
}

func printAuditSARIF(report auditReport) error {
	// Build rule index — deduplicate by CheckID
	ruleIndex := map[string]int{}
	var rules []sarifRule
	for _, f := range report.Findings {
		if _, exists := ruleIndex[f.CheckID]; exists {
			continue
		}
		ruleIndex[f.CheckID] = len(rules)
		rule := sarifRule{
			ID:               f.CheckID,
			ShortDescription: sarifMessage{Text: f.Title},
			DefaultConfig:    sarifDefaultConfig{Level: auditSeverityToSARIFLevel(f.Severity)},
		}
		if f.Product != "" {
			rule.Properties = sarifProperties{Product: f.Product}
		}
		rules = append(rules, rule)
	}

	var results []sarifResult
	for _, f := range report.Findings {
		results = append(results, sarifResult{
			RuleID:  f.CheckID,
			Level:   auditSeverityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s — %s", f.Title, f.Detail)},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "oktsec",
					InformationURI: "https://github.com/oktsec/oktsec",
					Version:        version,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
