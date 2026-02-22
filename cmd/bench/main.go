package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
)

func main() {
	dir, _ := os.MkdirTemp("", "oktsec-bench-*")
	defer func() { _ = os.RemoveAll(dir) }()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "bench.db"), logger, 30)
	if err != nil {
		panic(err)
	}
	defer func() { _ = store.Close() }()

	statuses := []string{"delivered", "delivered", "delivered", "blocked", "quarantined", "rejected"}
	rules := `[{"rule_id":"IAP-001","name":"Inter-agent relay injection","severity":"HIGH","match":"test data"}]`

	scales := []int{1000, 10000, 50000, 100000, 500000, 1000000}

	fmt.Println("=== SCALING BENCHMARK (24h time-window analytics) ===")
	fmt.Println()

	written := 0
	for _, target := range scales {
		toWrite := target - written
		if toWrite <= 0 {
			continue
		}

		start := time.Now()
		batchSize := 500
		for i := 0; i < toWrite; i += batchSize {
			end := i + batchSize
			if end > toWrite {
				end = toWrite
			}
			tx, _ := store.DB().Begin()
			for j := i; j < end; j++ {
				idx := written + j
				// 5K rows within 24h, rest older (simulates steady-state with retention)
				var ts string
				if idx < 5000 {
					ts = time.Now().Add(-time.Duration(idx) * time.Second).UTC().Format(time.RFC3339)
				} else {
					ts = time.Now().Add(-48*time.Hour - time.Duration(idx)*time.Second).UTC().Format(time.RFC3339)
				}
				_, _ = tx.Exec(
					`INSERT INTO audit_log (id, timestamp, from_agent, to_agent, content_hash, signature_verified, pubkey_fingerprint, status, rules_triggered, policy_decision, latency_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
					fmt.Sprintf("e-%07d", idx), ts,
					fmt.Sprintf("agent-%d", idx%6), fmt.Sprintf("agent-%d", (idx+3)%6),
					"e3b0c44298fc1c149afbf4c8996fb924", 0, "",
					statuses[idx%len(statuses)],
					rules, "test", int64(idx%50),
				)
			}
			_ = tx.Commit()
		}
		written = target
		fillTime := time.Since(start)
		insertRate := float64(toWrite) / fillTime.Seconds()

		// Update query planner statistics after bulk insert
		_, _ = store.DB().Exec("ANALYZE")

		type benchmark struct {
			name string
			fn   func()
		}
		benchmarks := []benchmark{
			{"Recent 50", func() { _, _ = store.Query(audit.QueryOpts{Limit: 50}) }},
			{"Stats (all rows)", func() { _, _ = store.QueryStats() }},
			{"Search LIKE", func() { _, _ = store.Query(audit.QueryOpts{Search: "agent-3", Limit: 50}) }},
			{"Hourly stats (24h)", func() { _, _ = store.QueryHourlyStats() }},
			{"Top rules (24h)", func() { _, _ = store.QueryTopRules(15) }},
			{"Agent risk (24h)", func() { _, _ = store.QueryAgentRisk() }},
		}

		fi, _ := os.Stat(filepath.Join(dir, "bench.db"))
		wal, _ := os.Stat(filepath.Join(dir, "bench.db-wal"))
		dbMB := float64(fi.Size()) / (1024 * 1024)
		walMB := float64(0)
		if wal != nil {
			walMB = float64(wal.Size()) / (1024 * 1024)
		}

		fmt.Printf("--- %dk rows (5k in 24h) | %.0f MB | %.0f ins/sec ---\n",
			written/1000, dbMB+walMB, insertRate)

		iters := 20
		if written >= 500000 {
			iters = 5
		}
		for _, b := range benchmarks {
			start := time.Now()
			for range iters {
				b.fn()
			}
			elapsed := time.Since(start)
			avgMs := float64(elapsed.Microseconds()) / float64(iters) / 1000.0
			fmt.Printf("  %-22s %7.1f ms\n", b.name, avgMs)
		}
		fmt.Println()
	}
}
