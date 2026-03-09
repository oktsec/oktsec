package commands

import (
	"os"

	"github.com/oktsec/oktsec/internal/auditcheck"
)

func printAuditSARIF(report auditReport) error {
	sarif := auditcheck.BuildSARIF(report.Findings, version)
	return auditcheck.WriteSARIF(os.Stdout, sarif)
}
