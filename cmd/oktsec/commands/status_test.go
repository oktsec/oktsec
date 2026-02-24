package commands

import (
	"testing"

	"github.com/oktsec/oktsec/internal/auditcheck"
)

// CLI-layer test: verify status output helpers still work with auditcheck types.

func TestPrintTopIssues_NoHighFindings(t *testing.T) {
	// Should not panic with only medium/info findings.
	findings := []auditcheck.Finding{
		{Severity: auditcheck.Medium, CheckID: "MON-002"},
		{Severity: auditcheck.Info, CheckID: "RET-003"},
	}
	// Just verify it doesn't panic.
	printTopIssues(findings)
}
