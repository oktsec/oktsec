package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/auditcheck"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

// Type aliases for backward-compatibility within this package (tests, SARIF).
type AuditSeverity = auditcheck.Severity
type AuditFinding = auditcheck.Finding
type auditSummary = auditcheck.Summary

const (
	AuditInfo     = auditcheck.Info
	AuditLow      = auditcheck.Low
	AuditMedium   = auditcheck.Medium
	AuditHigh     = auditcheck.High
	AuditCritical = auditcheck.Critical
)

// auditReport is the full audit output.
type auditReport struct {
	ConfigPath string              `json:"config_path"`
	Findings   []auditcheck.Finding `json:"findings"`
	KeysLoaded int                 `json:"keys_loaded"`
	AgentCount int                 `json:"agent_count"`
	Detected   []string            `json:"detected"`
	Summary    auditcheck.Summary  `json:"summary"`
}

func newAuditCmd() *cobra.Command {
	var jsonOutput bool
	var sarifOutput bool

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Check deployment security configuration",
		Long:  "Analyzes the oktsec configuration file and filesystem state, producing a security report with actionable findings.",
		Example: `  oktsec audit
  oktsec audit --json
  oktsec audit --sarif
  oktsec audit --config /path/to/oktsec.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			configDir := filepath.Dir(cfgFile)
			if configDir == "." {
				if wd, err := os.Getwd(); err == nil {
					configDir = wd
				}
			}

			findings, detected, _ := auditcheck.RunChecks(cfg, configDir)

			// Count keys
			keysLoaded := 0
			if cfg.Identity.KeysDir != "" {
				keysDir := cfg.Identity.KeysDir
				if !filepath.IsAbs(keysDir) {
					keysDir = filepath.Join(configDir, keysDir)
				}
				ks := identity.NewKeyStore()
				if err := ks.LoadFromDir(keysDir); err == nil {
					keysLoaded = ks.Count()
				}
			}

			report := auditReport{
				ConfigPath: cfgFile,
				Findings:   findings,
				KeysLoaded: keysLoaded,
				AgentCount: len(cfg.Agents),
				Detected:   detected,
				Summary:    auditcheck.Summarize(findings),
			}

			if sarifOutput {
				return printAuditSARIF(report)
			}
			if jsonOutput {
				return printAuditJSON(report)
			}
			printAuditTerminal(report)

			if report.Summary.Critical > 0 || report.Summary.High > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&sarifOutput, "sarif", false, "output as SARIF v2.1.0")
	return cmd
}

// --- Output formatters (CLI-specific) ---

func printAuditTerminal(report auditReport) {
	fmt.Println()
	fmt.Println("  oktsec audit")
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Config:     %s\n", report.ConfigPath)
	fmt.Printf("  Agents:     %d\n", report.AgentCount)
	fmt.Printf("  Keys:       %d loaded\n", report.KeysLoaded)
	if len(report.Detected) > 0 {
		fmt.Printf("  Detected:   %s\n", strings.Join(report.Detected, ", "))
	}

	// Group findings by product, then by severity
	products := []string{""} // oktsec first (empty product)
	products = append(products, report.Detected...)

	byProduct := map[string][]auditcheck.Finding{}
	for _, f := range report.Findings {
		byProduct[f.Product] = append(byProduct[f.Product], f)
	}

	for _, product := range products {
		pFindings := byProduct[product]
		if len(pFindings) == 0 {
			continue
		}

		fmt.Println()
		if product == "" {
			fmt.Println("  OKTSEC")
		} else {
			fmt.Printf("  %s\n", strings.ToUpper(product))
		}

		bySeverity := map[auditcheck.Severity][]auditcheck.Finding{}
		for _, f := range pFindings {
			bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
		}

		for _, sev := range []auditcheck.Severity{auditcheck.Critical, auditcheck.High, auditcheck.Medium, auditcheck.Low, auditcheck.Info} {
			group := bySeverity[sev]
			if len(group) == 0 {
				continue
			}
			fmt.Printf("    %s (%d)\n", sev, len(group))
			for _, f := range group {
				fmt.Printf("      [%s] %s\n", f.CheckID, f.Title)
				fmt.Printf("                %s\n", f.Detail)
			}
		}
	}

	fmt.Println()
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Findings: %d critical, %d high, %d medium, %d info\n",
		report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Info)
	fmt.Println()
}

func printAuditJSON(report auditReport) error {
	type jsonFinding struct {
		Severity string `json:"severity"`
		CheckID  string `json:"check_id"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		Product  string `json:"product,omitempty"`
	}
	type jsonReport struct {
		ConfigPath string             `json:"config_path"`
		Findings   []jsonFinding      `json:"findings"`
		KeysLoaded int                `json:"keys_loaded"`
		AgentCount int                `json:"agent_count"`
		Detected   []string           `json:"detected"`
		Summary    auditcheck.Summary `json:"summary"`
	}

	jr := jsonReport{
		ConfigPath: report.ConfigPath,
		KeysLoaded: report.KeysLoaded,
		AgentCount: report.AgentCount,
		Detected:   report.Detected,
		Summary:    report.Summary,
	}
	if jr.Detected == nil {
		jr.Detected = []string{}
	}
	for _, f := range report.Findings {
		jr.Findings = append(jr.Findings, jsonFinding{
			Severity: f.Severity.String(),
			CheckID:  f.CheckID,
			Title:    f.Title,
			Detail:   f.Detail,
			Product:  f.Product,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}
