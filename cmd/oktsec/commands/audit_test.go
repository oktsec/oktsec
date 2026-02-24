package commands

import (
	"testing"

	"github.com/oktsec/oktsec/internal/auditcheck"
	"github.com/stretchr/testify/assert"
)

// CLI-layer tests: verify the output formatters and type aliases work correctly.

func TestAuditSeverityAlias(t *testing.T) {
	// Verify that the package-level aliases match auditcheck constants.
	assert.Equal(t, auditcheck.Info, AuditInfo)
	assert.Equal(t, auditcheck.Low, AuditLow)
	assert.Equal(t, auditcheck.Medium, AuditMedium)
	assert.Equal(t, auditcheck.High, AuditHigh)
	assert.Equal(t, auditcheck.Critical, AuditCritical)
}

func TestAuditReportSummary(t *testing.T) {
	findings := []AuditFinding{
		{Severity: AuditCritical, CheckID: "SIG-001"},
		{Severity: AuditHigh, CheckID: "ACL-001"},
		{Severity: AuditMedium, CheckID: "MON-002"},
		{Severity: AuditInfo, CheckID: "RET-003"},
	}
	summary := auditcheck.Summarize(findings)
	assert.Equal(t, 1, summary.Critical)
	assert.Equal(t, 1, summary.High)
	assert.Equal(t, 1, summary.Medium)
	assert.Equal(t, 0, summary.Low)
	assert.Equal(t, 1, summary.Info)
}
