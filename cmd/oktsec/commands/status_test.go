package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeHealthScore_Perfect(t *testing.T) {
	findings := []AuditFinding{
		{Severity: AuditInfo, CheckID: "RET-003"},
	}
	score, grade := computeHealthScore(findings)
	assert.Equal(t, 100, score)
	assert.Equal(t, "A", grade)
}

func TestComputeHealthScore_NoFindings(t *testing.T) {
	score, grade := computeHealthScore(nil)
	assert.Equal(t, 100, score)
	assert.Equal(t, "A", grade)
}

func TestComputeHealthScore_OneCritical(t *testing.T) {
	findings := []AuditFinding{
		{Severity: AuditCritical, CheckID: "SIG-001"},
	}
	score, grade := computeHealthScore(findings)
	assert.Equal(t, 75, score)
	assert.Equal(t, "B", grade)
}

func TestComputeHealthScore_ManyIssues(t *testing.T) {
	findings := []AuditFinding{
		{Severity: AuditCritical, CheckID: "SIG-001"}, // -25
		{Severity: AuditCritical, CheckID: "NET-001"}, // -25
		{Severity: AuditHigh, CheckID: "ACL-001"},     // -15
		{Severity: AuditHigh, CheckID: "ACL-002"},     // -15
		{Severity: AuditMedium, CheckID: "MON-002"},   // -5
	}
	score, grade := computeHealthScore(findings)
	assert.Equal(t, 15, score) // 100 - 25 - 25 - 15 - 15 - 5
	assert.Equal(t, "F", grade)
}

func TestComputeHealthScore_FloorAtZero(t *testing.T) {
	findings := []AuditFinding{
		{Severity: AuditCritical},
		{Severity: AuditCritical},
		{Severity: AuditCritical},
		{Severity: AuditCritical},
		{Severity: AuditCritical}, // 5 * -25 = -125
	}
	score, grade := computeHealthScore(findings)
	assert.Equal(t, 0, score)
	assert.Equal(t, "F", grade)
}

func TestComputeHealthScore_GradeBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		findings []AuditFinding
		score    int
		grade    string
	}{
		{"perfect", nil, 100, "A"},
		{"one medium", []AuditFinding{{Severity: AuditMedium}}, 95, "A"},            // 100-5=95
		{"two medium", []AuditFinding{{Severity: AuditMedium}, {Severity: AuditMedium}}, 90, "A"}, // 100-10=90
		{"one high", []AuditFinding{{Severity: AuditHigh}}, 85, "B"},                 // 100-15=85
		{"crit+high", []AuditFinding{{Severity: AuditCritical}, {Severity: AuditHigh}}, 60, "C"}, // 100-25-15=60
		{"two crit", []AuditFinding{{Severity: AuditCritical}, {Severity: AuditCritical}}, 50, "D"}, // 100-50=50
		{"three crit", []AuditFinding{{Severity: AuditCritical}, {Severity: AuditCritical}, {Severity: AuditCritical}}, 25, "F"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade := computeHealthScore(tt.findings)
			assert.Equal(t, tt.score, score)
			assert.Equal(t, tt.grade, grade)
		})
	}
}

func TestComputeHealthScore_MediumOnly(t *testing.T) {
	findings := []AuditFinding{
		{Severity: AuditMedium}, // -5
		{Severity: AuditMedium}, // -5
		{Severity: AuditMedium}, // -5
	}
	score, grade := computeHealthScore(findings)
	assert.Equal(t, 85, score)
	assert.Equal(t, "B", grade)
}
