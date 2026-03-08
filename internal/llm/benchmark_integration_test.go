//go:build integration

package llm

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/engine"
)

func TestLLMBenchmarkIntegration(t *testing.T) {
	scanner := engine.NewScanner("")
	defer scanner.Close()

	ctx := context.Background()

	// Create an OpenAI-compatible analyzer pointing to local Ollama.
	llmCfg := Config{
		Enabled:   true,
		Provider:  ProviderOpenAICompat,
		Model:     "qwen3.5:latest",
		BaseURL:   "http://localhost:11434/v1",
		MaxTokens: 2048,
		Timeout:   "120s",
	}

	analyzer, err := New(llmCfg)
	if err != nil {
		t.Fatalf("failed to create LLM analyzer: %v", err)
	}
	if analyzer == nil {
		t.Fatal("analyzer is nil (LLM disabled?)")
	}

	rulesCount := scanner.RulesCount(ctx)

	fmt.Printf("\n")
	fmt.Printf("===========================================================================================================================================================\n")
	fmt.Printf("  Deterministic vs LLM Comparison (%d Aguara rules, LLM: %s)\n", rulesCount, analyzer.Name())
	fmt.Printf("===========================================================================================================================================================\n")
	fmt.Printf("\n")
	fmt.Printf("%-22s %-9s | %-10s %-6s %-10s | %-8s %-12s %-30s %-10s\n",
		"Case", "Expected", "D.Verdict", "D.Rul", "D.Latency", "L.Risk", "L.Action", "L.Threats", "L.Latency")
	fmt.Printf("%s\n", strings.Repeat("-", 145))

	type combinedResult struct {
		caseName    string
		expected    string
		detVerdict  engine.ScanVerdict
		detRules    int
		detLatency  time.Duration
		llmRisk     float64
		llmAction   string
		llmThreats  int
		llmLatency  time.Duration
		llmTokens   int
		detDetected bool
		llmDetected bool
	}

	results := make([]combinedResult, 0, len(benchmarkCases))

	for _, bc := range benchmarkCases {
		// --- Deterministic scan ---
		detStart := time.Now()
		outcome, err := scanner.ScanContent(ctx, bc.Content)
		detElapsed := time.Since(detStart)
		if err != nil {
			t.Errorf("deterministic scan failed for %s: %v", bc.Name, err)
			continue
		}

		// --- LLM analysis ---
		llmCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
		req := AnalysisRequest{
			MessageID:      fmt.Sprintf("bench-%s", bc.Name),
			FromAgent:      bc.FromAgent,
			ToAgent:        bc.ToAgent,
			Content:        bc.Content,
			CurrentVerdict: outcome.Verdict,
			Findings:       outcome.Findings,
			Timestamp:      time.Now(),
		}

		llmResult, llmErr := analyzer.Analyze(llmCtx, req)
		cancel()

		cr := combinedResult{
			caseName:   bc.Name,
			expected:   bc.ExpectedRisk,
			detVerdict: outcome.Verdict,
			detRules:   len(outcome.Findings),
			detLatency: detElapsed,
		}

		cr.detDetected = bc.ExpectedRisk != "benign" && outcome.Verdict != engine.VerdictClean
		if bc.ExpectedRisk == "benign" && outcome.Verdict == engine.VerdictClean {
			cr.detDetected = true // true negative counts as correct
		}

		llmRiskStr := "ERR"
		llmActionStr := "ERR"
		llmThreatsStr := "ERR"
		llmLatStr := "-"

		if llmErr != nil {
			t.Logf("LLM failed for %s: %v", bc.Name, llmErr)
			cr.llmRisk = -1
			cr.llmAction = "error"
		} else {
			cr.llmRisk = llmResult.RiskScore
			cr.llmAction = llmResult.RecommendedAction
			cr.llmThreats = len(llmResult.Threats)
			cr.llmLatency = time.Duration(llmResult.LatencyMs) * time.Millisecond
			cr.llmTokens = llmResult.TokensUsed

			llmRiskStr = fmt.Sprintf("%.0f", llmResult.RiskScore)
			llmActionStr = llmResult.RecommendedAction
			llmThreatsStr = fmt.Sprintf("%d threats", len(llmResult.Threats))
			llmLatStr = cr.llmLatency.Round(time.Millisecond).String()

			cr.llmDetected = bc.ExpectedRisk != "benign" && llmResult.RiskScore > 30
			if bc.ExpectedRisk == "benign" && llmResult.RiskScore <= 0.3 {
				cr.llmDetected = true // true negative
			}
		}

		if len(llmActionStr) > 12 {
			llmActionStr = llmActionStr[:12]
		}
		if len(llmThreatsStr) > 30 {
			llmThreatsStr = llmThreatsStr[:30]
		}

		fmt.Printf("%-22s %-9s | %-10s %-6d %-10s | %-8s %-12s %-30s %-10s\n",
			bc.Name, bc.ExpectedRisk,
			outcome.Verdict, len(outcome.Findings), detElapsed.Round(time.Microsecond),
			llmRiskStr, llmActionStr, llmThreatsStr, llmLatStr)

		results = append(results, cr)
	}

	fmt.Printf("%s\n", strings.Repeat("-", 145))

	// --- Summary stats ---
	var totalDetRules int
	var totalDetLatency time.Duration
	var totalLLMRisk float64
	var totalLLMLatency time.Duration
	var totalLLMTokens int
	var llmSuccessCount int
	var agreements int

	for _, r := range results {
		totalDetRules += r.detRules
		totalDetLatency += r.detLatency
		if r.llmRisk >= 0 {
			totalLLMRisk += r.llmRisk
			totalLLMLatency += r.llmLatency
			totalLLMTokens += r.llmTokens
			llmSuccessCount++
		}
		// Agreement: both detected threat or both said clean
		detClean := r.detVerdict == engine.VerdictClean
		llmClean := r.llmRisk >= 0 && r.llmRisk <= 10
		if r.llmRisk >= 0 {
			if (detClean && llmClean) || (!detClean && !llmClean) {
				agreements++
			}
		}
	}

	n := len(results)
	fmt.Printf("\n")
	fmt.Printf("Summary Statistics:\n")
	fmt.Printf("  Cases analyzed: %d\n", n)
	fmt.Printf("\n")
	fmt.Printf("  Deterministic Engine:\n")
	fmt.Printf("    Total rules triggered:  %d\n", totalDetRules)
	if n > 0 {
		fmt.Printf("    Avg latency:            %s\n", (totalDetLatency / time.Duration(n)).Round(time.Microsecond))
	}
	fmt.Printf("\n")
	fmt.Printf("  LLM (%s):\n", analyzer.Name())
	if llmSuccessCount > 0 {
		fmt.Printf("    Successful analyses:    %d/%d\n", llmSuccessCount, n)
		fmt.Printf("    Avg risk score:         %.1f / 100\n", totalLLMRisk/float64(llmSuccessCount))
		fmt.Printf("    Avg latency:            %s\n", (totalLLMLatency / time.Duration(llmSuccessCount)).Round(time.Millisecond))
		fmt.Printf("    Avg tokens:             %d\n", totalLLMTokens/llmSuccessCount)
	} else {
		fmt.Printf("    No successful LLM analyses (is Ollama running?)\n")
	}
	fmt.Printf("\n")
	if llmSuccessCount > 0 {
		fmt.Printf("  Agreement rate:           %d/%d (%.1f%%)\n",
			agreements, llmSuccessCount, float64(agreements)/float64(llmSuccessCount)*100)
		fmt.Printf("  (Agreement = both detect threat OR both say clean)\n")
	}
	fmt.Printf("\n")
}
