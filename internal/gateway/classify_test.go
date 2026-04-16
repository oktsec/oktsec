package gateway

import "testing"

func TestClassifyTool(t *testing.T) {
	tests := []struct {
		name        string
		description string
		wantImpact  ImpactTier
		wantGen     Generality
		wantRisk    RiskTier
	}{
		{"read_file", "Read a file from disk", ImpactPerception, GeneralityNarrow, RiskLow},
		{"list_repos", "List GitHub repositories", ImpactPerception, GeneralityNarrow, RiskLow},
		{"search", "Search the web for information", ImpactPerception, GeneralityNarrow, RiskLow},
		{"create_issue", "Create a GitHub issue", ImpactAction, GeneralityNarrow, RiskMedium},
		{"send_email", "Send an email to a user", ImpactAction, GeneralityNarrow, RiskMedium},
		{"bash", "Execute shell commands", ImpactAction, GeneralityGeneral, RiskHigh},
		{"computer_use", "Control the computer", ImpactAction, GeneralityGeneral, RiskHigh},
		{"browser_navigate", "Navigate browser to URL and click elements", ImpactAction, GeneralityGeneral, RiskHigh},
		{"crypto_transfer", "Transfer cryptocurrency to wallet", ImpactAction, GeneralityNarrow, RiskHigh},
		{"stripe_checkout", "Create a Stripe checkout session", ImpactAction, GeneralityNarrow, RiskHigh},
		{"get_wallet_balance", "Read the wallet balance", ImpactPerception, GeneralityNarrow, RiskMedium},
		{"list_invoices", "List user invoices", ImpactPerception, GeneralityNarrow, RiskMedium},
		{"analyze_trades", "Analyze recent trades for patterns", ImpactReasoning, GeneralityNarrow, RiskMedium},
		{"analyze_data", "Analyze dataset and summarize findings", ImpactReasoning, GeneralityNarrow, RiskLow},
		{"web_search", "Search the web for results", ImpactPerception, GeneralityNarrow, RiskLow},
		{"", "", ImpactReasoning, GeneralityNarrow, RiskLow},
		{"unknown_tool", "", ImpactReasoning, GeneralityNarrow, RiskLow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyTool(tc.name, tc.description)
			if got.ImpactTier != tc.wantImpact {
				t.Errorf("impact: got %q, want %q", got.ImpactTier, tc.wantImpact)
			}
			if got.Generality != tc.wantGen {
				t.Errorf("generality: got %q, want %q", got.Generality, tc.wantGen)
			}
			if got.RiskTier != tc.wantRisk {
				t.Errorf("risk: got %q, want %q", got.RiskTier, tc.wantRisk)
			}
		})
	}
}

func TestClassifyTool_MatchedKeywords(t *testing.T) {
	c := ClassifyTool("bash", "Execute shell commands")
	if len(c.MatchedKeywords) == 0 {
		t.Error("expected matched keywords, got none")
	}
}

func TestDeriveRiskTier(t *testing.T) {
	tests := []struct {
		impact     ImpactTier
		gen        Generality
		hasFinance bool
		want       RiskTier
	}{
		{ImpactPerception, GeneralityNarrow, false, RiskLow},
		{ImpactReasoning, GeneralityNarrow, false, RiskLow},
		{ImpactAction, GeneralityNarrow, false, RiskMedium},
		{ImpactPerception, GeneralityGeneral, false, RiskMedium},
		{ImpactReasoning, GeneralityGeneral, false, RiskMedium},
		{ImpactAction, GeneralityGeneral, false, RiskHigh},
		{ImpactAction, GeneralityGeneral, true, RiskCritical},
		{ImpactAction, GeneralityNarrow, true, RiskHigh},
		{ImpactPerception, GeneralityNarrow, true, RiskMedium},
		{ImpactReasoning, GeneralityNarrow, true, RiskMedium},
	}

	for _, tc := range tests {
		got := deriveRiskTier(tc.impact, tc.gen, tc.hasFinance)
		if got != tc.want {
			t.Errorf("deriveRiskTier(%s, %s, %v) = %s, want %s",
				tc.impact, tc.gen, tc.hasFinance, got, tc.want)
		}
	}
}
