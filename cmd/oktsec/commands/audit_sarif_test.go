package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintAuditSARIF_Structure(t *testing.T) {
	report := auditReport{
		ConfigPath: "oktsec.yaml",
		Findings: []AuditFinding{
			{Severity: AuditCritical, CheckID: "SIG-001", Title: "Signatures not required", Detail: "detail1"},
			{Severity: AuditHigh, CheckID: "ACL-001", Title: "Default allow", Detail: "detail2"},
			{Severity: AuditMedium, CheckID: "MON-002", Title: "No webhooks", Detail: "detail3"},
			{Severity: AuditInfo, CheckID: "RET-003", Title: "DB present", Detail: "detail4"},
			{Severity: AuditHigh, CheckID: "OC-004", Title: "Open DM", Detail: "detail5", Product: "OpenClaw"},
		},
		Detected: []string{"OpenClaw"},
		Summary:  auditSummary{Critical: 1, High: 2, Medium: 1, Info: 1},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printAuditSARIF(report)
	require.NoError(t, err)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	// Verify top-level SARIF structure
	assert.Equal(t, "2.1.0", log.Version)
	assert.Contains(t, log.Schema, "sarif-schema-2.1.0")
	require.Len(t, log.Runs, 1)

	run := log.Runs[0]

	// Tool metadata
	assert.Equal(t, "oktsec", run.Tool.Driver.Name)
	assert.Contains(t, run.Tool.Driver.InformationURI, "oktsec")

	// Rules — one per unique CheckID
	assert.Len(t, run.Tool.Driver.Rules, 5)
	ruleIDs := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ruleIDs[r.ID] = true
	}
	assert.True(t, ruleIDs["SIG-001"])
	assert.True(t, ruleIDs["OC-004"])

	// Results — one per finding
	assert.Len(t, run.Results, 5)
}

func TestAuditSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		sev  AuditSeverity
		want string
	}{
		{AuditCritical, "error"},
		{AuditHigh, "error"},
		{AuditMedium, "warning"},
		{AuditLow, "note"},
		{AuditInfo, "note"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, auditSeverityToSARIFLevel(tt.sev), "severity=%s", tt.sev)
	}
}

func TestSARIF_ProductInRuleProperties(t *testing.T) {
	report := auditReport{
		Findings: []AuditFinding{
			{Severity: AuditHigh, CheckID: "OC-001", Title: "Gateway exposed", Detail: "d", Product: "OpenClaw"},
			{Severity: AuditHigh, CheckID: "SIG-001", Title: "No sigs", Detail: "d"},
		},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_ = printAuditSARIF(report)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	rules := log.Runs[0].Tool.Driver.Rules
	require.Len(t, rules, 2)

	// OC-001 should have product property
	assert.Equal(t, "OpenClaw", rules[0].Properties.Product)
	// SIG-001 should not
	assert.Empty(t, rules[1].Properties.Product)
}

func TestSARIF_EmptyFindings(t *testing.T) {
	report := auditReport{Findings: nil}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printAuditSARIF(report)
	require.NoError(t, err)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	assert.Empty(t, log.Runs[0].Results)
	assert.Empty(t, log.Runs[0].Tool.Driver.Rules)
}
