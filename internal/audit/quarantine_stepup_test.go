package audit

import "testing"

// Step-up approvals are single-use: the first consume spends the
// approved item; the second finds nothing.
func TestConsumeStepUpApprovalSingleUse(t *testing.T) {
	s := newTestStore(t)
	item := QuarantineItem{
		ID: "su-1", AuditEntryID: "su-1", Content: "{}", FromAgent: "payments-agent",
		ToAgent: "transfer_funds", Status: QStatusPending,
		ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-06-12T00:00:00Z",
		RulesTriggered: "[]", Timestamp: "2026-06-12T00:00:00Z",
	}
	if err := s.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	// Pending is not consumable.
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds"); ok {
		t.Fatal("pending item must not be consumable")
	}
	if err := s.QuarantineApprove("su-1", "operator"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeStepUpApproval("payments-agent", "transfer_funds"); err != nil || !ok {
		t.Fatalf("approved item not consumed: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds"); ok {
		t.Fatal("approval was spent twice")
	}
	// Wrong (agent, tool) never consumes someone else's approval.
	if ok, _ := s.ConsumeStepUpApproval("other-agent", "transfer_funds"); ok {
		t.Fatal("foreign agent consumed the approval")
	}
}
