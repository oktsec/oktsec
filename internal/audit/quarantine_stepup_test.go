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
		RulesTriggered: StepUpMarker, Timestamp: "2026-06-12T00:00:00Z",
	}
	if err := s.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	// Pending is not consumable.
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", "{}"); ok {
		t.Fatal("pending item must not be consumable")
	}
	if err := s.QuarantineApprove("su-1", "operator"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", "{}"); err != nil || !ok {
		t.Fatalf("approved item not consumed: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", "{}"); ok {
		t.Fatal("approval was spent twice")
	}
	// Wrong (agent, tool) never consumes someone else's approval.
	if ok, _ := s.ConsumeStepUpApproval("other-agent", "transfer_funds", "{}"); ok {
		t.Fatal("foreign agent consumed the approval")
	}
}

// Approval binds to the exact reviewed arguments and to the step-up
// marker: different args or a content-quarantine item never consume.
func TestConsumeStepUpApprovalBinding(t *testing.T) {
	s := newTestStore(t)
	stepUp := QuarantineItem{
		ID: "su-2", AuditEntryID: "su-2", Content: `{"amount":600}`, FromAgent: "payments-agent",
		ToAgent: "transfer_funds", Status: QStatusPending,
		ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-06-12T00:00:00Z",
		RulesTriggered: StepUpMarker, Timestamp: "2026-06-12T00:00:00Z",
	}
	if err := s.Enqueue(stepUp); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineApprove("su-2", "operator"); err != nil {
		t.Fatal(err)
	}
	// Different arguments never spend the approval.
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", `{"amount":50000}`); ok {
		t.Fatal("approval spent for different arguments")
	}
	// A content-quarantine approval (no marker) is not a step-up pass.
	content := QuarantineItem{
		ID: "cq-1", AuditEntryID: "cq-1", Content: `{"amount":600}`, FromAgent: "payments-agent",
		ToAgent: "transfer_funds", Status: QStatusPending,
		ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-06-12T00:00:00Z",
		RulesTriggered: "[]", Timestamp: "2026-06-12T00:00:00Z",
	}
	if err := s.Enqueue(content); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineApprove("cq-1", "operator"); err != nil {
		t.Fatal(err)
	}
	// Exact match spends the step-up item; the content item stays.
	if ok, err := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", `{"amount":600}`); err != nil || !ok {
		t.Fatalf("exact-args consume failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", `{"amount":600}`); ok {
		t.Fatal("content-quarantine approval was spent as a step-up pass")
	}

	// An expired approval never consumes.
	expired := QuarantineItem{
		ID: "su-3", AuditEntryID: "su-3", Content: `{"amount":700}`, FromAgent: "payments-agent",
		ToAgent: "transfer_funds", Status: QStatusPending,
		ExpiresAt: "2020-01-01T00:00:00Z", CreatedAt: "2026-06-12T00:00:00Z",
		RulesTriggered: StepUpMarker, Timestamp: "2026-06-12T00:00:00Z",
	}
	if err := s.Enqueue(expired); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineApprove("su-3", "operator"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeStepUpApproval("payments-agent", "transfer_funds", `{"amount":700}`); ok {
		t.Fatal("expired approval was spent")
	}
}

// The expiry job flips approved-but-expired step-up tokens to expired
// so the UI never advertises an approval that can no longer be spent;
// approved CONTENT items (terminal release records) stay approved.
func TestQuarantineExpireOldCoversApprovedStepUps(t *testing.T) {
	s := newTestStore(t)
	old := QuarantineItem{
		ID: "su-old", AuditEntryID: "su-old", Content: "{}", FromAgent: "a",
		ToAgent: "t", Status: QStatusPending,
		ExpiresAt: "2020-01-01T00:00:00Z", CreatedAt: "2019-12-31T00:00:00Z",
		RulesTriggered: StepUpMarker, Timestamp: "2019-12-31T00:00:00Z",
	}
	if err := s.Enqueue(old); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineApprove("su-old", "operator"); err != nil {
		t.Fatal(err)
	}
	contentApproved := QuarantineItem{
		ID: "cq-old", AuditEntryID: "cq-old", Content: "msg", FromAgent: "a",
		ToAgent: "b", Status: QStatusPending,
		ExpiresAt: "2020-01-01T00:00:00Z", CreatedAt: "2019-12-31T00:00:00Z",
		RulesTriggered: "[]", Timestamp: "2019-12-31T00:00:00Z",
	}
	if err := s.Enqueue(contentApproved); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineApprove("cq-old", "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QuarantineExpireOld(); err != nil {
		t.Fatal(err)
	}
	su, err := s.QuarantineByID("su-old")
	if err != nil || su == nil {
		t.Fatal(err)
	}
	if su.Status != QStatusExpired {
		t.Fatalf("step-up approval status = %s, want expired", su.Status)
	}
	cq, err := s.QuarantineByID("cq-old")
	if err != nil || cq == nil {
		t.Fatal(err)
	}
	if cq.Status != QStatusApproved {
		t.Fatalf("content approval status = %s, must stay approved", cq.Status)
	}
}
