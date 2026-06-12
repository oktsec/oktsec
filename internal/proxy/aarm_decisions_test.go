package proxy

import (
	"net/http"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/engine"
)

// verdictToResponse covers the full AARM decision vocabulary: modify
// delivers (200) as a modified action, step_up holds (202) for
// explicit approval.
func TestVerdictToResponseAARMVocabulary(t *testing.T) {
	cases := []struct {
		verdict    engine.ScanVerdict
		status     string
		decision   string
		httpStatus int
	}{
		{engine.VerdictClean, audit.StatusDelivered, audit.DecisionAllow, http.StatusOK},
		{engine.VerdictFlag, audit.StatusDelivered, audit.DecisionContentFlagged, http.StatusOK},
		{engine.VerdictModify, audit.StatusModified, audit.DecisionContentRedacted, http.StatusOK},
		{engine.VerdictStepUp, audit.StatusStepUp, audit.DecisionStepUpApproval, http.StatusAccepted},
		{engine.VerdictQuarantine, audit.StatusQuarantined, audit.DecisionContentQuarantined, http.StatusAccepted},
		{engine.VerdictBlock, audit.StatusBlocked, audit.DecisionContentBlocked, http.StatusForbidden},
	}
	for _, c := range cases {
		status, decision, httpStatus := verdictToResponse(c.verdict)
		if status != c.status || decision != c.decision || httpStatus != c.httpStatus {
			t.Fatalf("%s -> %s/%s/%d, want %s/%s/%d",
				c.verdict, status, decision, httpStatus, c.status, c.decision, c.httpStatus)
		}
	}
}
