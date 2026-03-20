package auditcheck

import (
	"encoding/json"
	"io"
	"sort"
)

// SARIF v2.1.0 types  - minimal subset for audit output.

// SARIFLog is the top-level SARIF v2.1.0 report.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool's identity.
type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule describes a rule with its default severity.
type SARIFRule struct {
	ID               string             `json:"id"`
	ShortDescription SARIFMessage       `json:"shortDescription"`
	DefaultConfig    SARIFDefaultConfig `json:"defaultConfiguration"`
	Properties       SARIFProperties    `json:"properties,omitempty"`
}

// SARIFDefaultConfig holds the default severity level.
type SARIFDefaultConfig struct {
	Level string `json:"level"`
}

// SARIFProperties holds additional rule metadata.
type SARIFProperties struct {
	Product string `json:"product,omitempty"`
}

// SARIFResult is a single finding result.
type SARIFResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message SARIFMessage `json:"message"`
}

// SARIFMessage wraps a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SeverityToSARIFLevel maps an audit severity to a SARIF level string.
func SeverityToSARIFLevel(s Severity) string {
	switch s {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	case Low, Info:
		return "note"
	default:
		return "none"
	}
}

// BuildSARIF constructs a SARIF report from audit findings.
func BuildSARIF(findings []Finding, toolVersion string) SARIFLog {
	ruleIndex := map[string]int{}
	var rules []SARIFRule
	for _, f := range findings {
		if _, exists := ruleIndex[f.CheckID]; exists {
			continue
		}
		ruleIndex[f.CheckID] = len(rules)
		rule := SARIFRule{
			ID:               f.CheckID,
			ShortDescription: SARIFMessage{Text: f.Title},
			DefaultConfig:    SARIFDefaultConfig{Level: SeverityToSARIFLevel(f.Severity)},
		}
		if f.Product != "" {
			rule.Properties = SARIFProperties{Product: f.Product}
		}
		rules = append(rules, rule)
	}

	// Deterministic order
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	var results []SARIFResult
	for _, f := range findings {
		msg := f.Title
		if f.Detail != "" {
			msg += "  - " + f.Detail
		}
		results = append(results, SARIFResult{
			RuleID:  f.CheckID,
			Level:   SeverityToSARIFLevel(f.Severity),
			Message: SARIFMessage{Text: msg},
		})
	}

	return SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "oktsec",
					InformationURI: "https://github.com/oktsec/oktsec",
					Version:        toolVersion,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

// WriteSARIF encodes a SARIF report to the writer with pretty-print indentation.
func WriteSARIF(w io.Writer, report SARIFLog) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
