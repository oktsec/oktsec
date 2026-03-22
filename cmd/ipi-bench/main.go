// cmd/ipi-bench/main.go
// Benchmark oktsec's scanner against the IPI Arena attack dataset.
// Usage: go run ./cmd/ipi-bench -dataset /path/to/ipi_arena_attacks.jsonl
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/engine"
)

type Attack struct {
	BehaviorID string `json:"behavior_id"`
	Content    string `json:"attack"`
}

type Result struct {
	BehaviorID string
	Verdict    engine.ScanVerdict
	Findings   []engine.FindingSummary
	ScanTimeMs float64
}

func main() {
	datasetPath := flag.String("dataset", "", "path to IPI Arena JSONL dataset")
	outputPath := flag.String("output", "", "path to write JSON results (optional)")
	llmMode := flag.Bool("llm", false, "run LLM benchmark against curated missed attacks (requires ANTHROPIC_API_KEY)")
	llmOutput := flag.String("llm-output", "", "path to write LLM evidence JSON")
	fullMode := flag.Bool("full", false, "run full benchmark: deterministic + LLM on missed (requires dataset + ANTHROPIC_API_KEY)")
	fullOutput := flag.String("full-output", "", "path to write full evidence JSON")
	flag.Parse()

	if *fullMode {
		if *datasetPath == "" {
			fmt.Fprintln(os.Stderr, "usage: ipi-bench -full -dataset /path/to/attacks.jsonl [-full-output results.json]")
			os.Exit(1)
		}
		runFullBenchmark(*datasetPath, *fullOutput)
		return
	}

	if *llmMode {
		runLLMBenchmark(*llmOutput)
		return
	}

	if *datasetPath == "" {
		fmt.Fprintln(os.Stderr, "usage: ipi-bench -dataset /path/to/ipi_arena_attacks.jsonl")
		fmt.Fprintln(os.Stderr, "       ipi-bench -llm [-llm-output results.json]")
		os.Exit(1)
	}

	// Load attacks
	attacks, err := loadAttacks(*datasetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading dataset: %v\n", err)
		os.Exit(1)
	}

	// Init scanner
	scanner := engine.NewScanner("")
	defer scanner.Close()

	ctx := context.Background()
	ruleCount := scanner.RulesCount(ctx)

	fmt.Printf("IPI Arena Benchmark\n")
	fmt.Printf("===================\n")
	fmt.Printf("Dataset:    %s\n", *datasetPath)
	fmt.Printf("Attacks:    %d\n", len(attacks))
	fmt.Printf("Rules:      %d\n", ruleCount)
	fmt.Printf("Timestamp:  %s\n\n", time.Now().UTC().Format(time.RFC3339))

	// Run scans
	var results []Result
	for _, atk := range attacks {
		start := time.Now()
		outcome, err := scanner.ScanContent(ctx, atk.Content)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error on %s: %v\n", atk.BehaviorID, err)
			continue
		}

		results = append(results, Result{
			BehaviorID: strings.TrimSpace(atk.BehaviorID),
			Verdict:    outcome.Verdict,
			Findings:   outcome.Findings,
			ScanTimeMs: float64(elapsed.Microseconds()) / 1000.0,
		})
	}

	// Compute stats
	printResults(results, ruleCount)

	// Write JSON output
	if *outputPath != "" {
		writeJSON(*outputPath, results, ruleCount)
	}
}

func loadAttacks(path string) ([]Attack, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var attacks []Attack
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for long attacks
	for s.Scan() {
		var a Attack
		if err := json.Unmarshal(s.Bytes(), &a); err != nil {
			return nil, fmt.Errorf("parse line: %w", err)
		}
		attacks = append(attacks, a)
	}
	return attacks, s.Err()
}

func printResults(results []Result, ruleCount int) {
	total := len(results)
	if total == 0 {
		fmt.Println("No results.")
		return
	}

	// Count by verdict
	verdicts := map[engine.ScanVerdict]int{}
	for _, r := range results {
		verdicts[r.Verdict]++
	}

	detected := total - verdicts[engine.VerdictClean]
	detectionRate := float64(detected) / float64(total) * 100

	fmt.Printf("Overall Results\n")
	fmt.Printf("---------------\n")
	fmt.Printf("Total attacks:   %d\n", total)
	fmt.Printf("Detected:        %d (%.1f%%)\n", detected, detectionRate)
	fmt.Printf("Missed:          %d (%.1f%%)\n", verdicts[engine.VerdictClean], 100-detectionRate)
	fmt.Printf("\n")

	fmt.Printf("By Verdict\n")
	fmt.Printf("----------\n")
	for _, v := range []engine.ScanVerdict{engine.VerdictBlock, engine.VerdictQuarantine, engine.VerdictFlag, engine.VerdictClean} {
		count := verdicts[v]
		pct := float64(count) / float64(total) * 100
		fmt.Printf("  %-12s %3d  (%5.1f%%)\n", v, count, pct)
	}
	fmt.Printf("\n")

	// Detection by behavior
	type behaviorStat struct {
		name     string
		total    int
		detected int
	}
	behaviorMap := map[string]*behaviorStat{}
	for _, r := range results {
		bs, ok := behaviorMap[r.BehaviorID]
		if !ok {
			bs = &behaviorStat{name: r.BehaviorID}
			behaviorMap[r.BehaviorID] = bs
		}
		bs.total++
		if r.Verdict != engine.VerdictClean {
			bs.detected++
		}
	}

	var behaviors []behaviorStat
	for _, bs := range behaviorMap {
		behaviors = append(behaviors, *bs)
	}
	sort.Slice(behaviors, func(i, j int) bool {
		ri := float64(behaviors[i].detected) / float64(behaviors[i].total)
		rj := float64(behaviors[j].detected) / float64(behaviors[j].total)
		return ri > rj
	})

	fmt.Printf("Detection by Behavior\n")
	fmt.Printf("---------------------\n")
	for _, bs := range behaviors {
		pct := float64(bs.detected) / float64(bs.total) * 100
		fmt.Printf("  %-45s %d/%d  (%5.1f%%)\n", bs.name, bs.detected, bs.total, pct)
	}
	fmt.Printf("\n")

	// Top triggered rules
	ruleCounts := map[string]int{}
	ruleNames := map[string]string{}
	for _, r := range results {
		for _, f := range r.Findings {
			ruleCounts[f.RuleID]++
			ruleNames[f.RuleID] = f.Name
		}
	}

	type ruleHit struct {
		id    string
		name  string
		count int
	}
	var ruleHits []ruleHit
	for id, count := range ruleCounts {
		ruleHits = append(ruleHits, ruleHit{id, ruleNames[id], count})
	}
	sort.Slice(ruleHits, func(i, j int) bool {
		return ruleHits[i].count > ruleHits[j].count
	})

	fmt.Printf("Top Triggered Rules\n")
	fmt.Printf("-------------------\n")
	limit := 20
	if len(ruleHits) < limit {
		limit = len(ruleHits)
	}
	for _, rh := range ruleHits[:limit] {
		fmt.Printf("  %-20s %3d hits  %s\n", rh.id, rh.count, rh.name)
	}
	fmt.Printf("\n")

	// Missed attacks (clean verdict)
	fmt.Printf("Missed Attacks (verdict: clean)\n")
	fmt.Printf("-------------------------------\n")
	for _, r := range results {
		if r.Verdict == engine.VerdictClean {
			preview := r.BehaviorID
			fmt.Printf("  %s\n", preview)
		}
	}
	fmt.Printf("\n")

	// Latency
	var totalMs float64
	for _, r := range results {
		totalMs += r.ScanTimeMs
	}
	avgMs := totalMs / float64(total)
	fmt.Printf("Scan Latency\n")
	fmt.Printf("------------\n")
	fmt.Printf("  Total:   %.1f ms\n", totalMs)
	fmt.Printf("  Average: %.2f ms/attack\n", avgMs)
}

type jsonOutput struct {
	Timestamp     string   `json:"timestamp"`
	RuleCount     int      `json:"rule_count"`
	TotalAttacks  int      `json:"total_attacks"`
	Detected      int      `json:"detected"`
	DetectionRate float64  `json:"detection_rate_pct"`
	Results       []Result `json:"results"`
}

func writeJSON(path string, results []Result, ruleCount int) {
	detected := 0
	for _, r := range results {
		if r.Verdict != engine.VerdictClean {
			detected++
		}
	}

	out := jsonOutput{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		RuleCount:     ruleCount,
		TotalAttacks:  len(results),
		Detected:      detected,
		DetectionRate: float64(detected) / float64(len(results)) * 100,
		Results:       results,
	}

	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
	} else {
		fmt.Printf("Results written to %s\n", path)
	}
}
