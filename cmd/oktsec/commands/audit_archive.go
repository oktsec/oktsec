package commands

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/spf13/cobra"
)

// newAuditArchiveCmd exports audit entries older than a cutoff to a
// gzipped JSONL file. Does NOT touch the live DB — use `audit prune` to
// delete after you've verified the archive is good.
//
// Why split archive from prune: an archived-but-still-in-DB state is safe
// (disk cost only). Prune is irreversible, so operators should verify the
// archive first.
func newAuditArchiveCmd() *cobra.Command {
	var (
		dbPath string
		before string
		output string
	)
	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Export audit entries older than a cutoff to a gzipped JSONL file",
		Long: `Opens the audit DB read-only, streams every audit_log row with
timestamp < --before into a gzip-compressed JSON-lines file. The live
database is left untouched. Run 'audit prune' afterwards to reclaim space.`,
		Example: `  oktsec audit archive --before=2026-01-01 --output=archive-2025.jsonl.gz`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				return fmt.Errorf("--output is required")
			}
			cutoff, err := parseCutoff(before)
			if err != nil {
				return err
			}
			if dbPath == "" {
				dbPath = resolveDBPath()
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			// Use read-only so archiving from a running system can't race
			// on auto-repair.
			store, err := audit.NewStoreReadOnly(dbPath, logger)
			if err != nil {
				return fmt.Errorf("opening audit db: %w", err)
			}
			defer func() { _ = store.Close() }()

			rows, err := store.DB().Query(
				`SELECT id, timestamp, from_agent, to_agent, COALESCE(tool_name,''),
				        content_hash, signature_verified, pubkey_fingerprint, status,
				        COALESCE(rules_triggered,''), policy_decision, latency_ms,
				        COALESCE(intent,''), COALESCE(session_id,''),
				        COALESCE(prev_hash,''), COALESCE(entry_hash,''), COALESCE(proxy_signature,'')
				 FROM audit_log WHERE timestamp < ? ORDER BY rowid ASC`, cutoff.UTC().Format(time.RFC3339))
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer func() { _ = rows.Close() }()

			f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("creating output: %w", err)
			}
			defer func() { _ = f.Close() }()
			gz := gzip.NewWriter(f)
			defer func() { _ = gz.Close() }()
			enc := json.NewEncoder(gz)

			var count int
			for rows.Next() {
				var rec archivedEntry
				if err := rows.Scan(&rec.ID, &rec.Timestamp, &rec.FromAgent, &rec.ToAgent, &rec.ToolName,
					&rec.ContentHash, &rec.SignatureVerified, &rec.PubkeyFingerprint, &rec.Status,
					&rec.RulesTriggered, &rec.PolicyDecision, &rec.LatencyMs,
					&rec.Intent, &rec.SessionID,
					&rec.PrevHash, &rec.EntryHash, &rec.ProxySignature); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				if err := enc.Encode(&rec); err != nil {
					return fmt.Errorf("encode: %w", err)
				}
				count++
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if err := gz.Close(); err != nil {
				return fmt.Errorf("closing gzip: %w", err)
			}
			fmt.Printf("archived %d entries before %s to %s\n", count, cutoff.Format("2006-01-02"), output)
			fmt.Println("run 'oktsec audit prune' when you've verified the archive.")
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to audit db")
	cmd.Flags().StringVar(&before, "before", "", "cutoff date YYYY-MM-DD (exclusive)")
	cmd.Flags().StringVar(&output, "output", "", "output path for the .jsonl.gz file")
	_ = cmd.MarkFlagRequired("before")
	return cmd
}

// newAuditPruneCmd deletes entries older than a cutoff. Requires --yes
// because this is destructive — callers are expected to have archived
// first (via `audit archive`).
func newAuditPruneCmd() *cobra.Command {
	var (
		dbPath string
		before string
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete audit entries older than a cutoff (destructive)",
		Long: `Permanently removes audit_log rows with timestamp < --before.
The chain remains verifiable for the rows that stay because the stored
entry_hash values are not touched. Requires --yes to actually run.`,
		Example: `  oktsec audit prune --before=2026-01-01 --yes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cutoff, err := parseCutoff(before)
			if err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("refusing to run without --yes (destructive)")
			}
			if dbPath == "" {
				dbPath = resolveDBPath()
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			// Prune is the writable path, not read-only — we're deleting.
			store, err := audit.NewStore(dbPath, logger)
			if err != nil {
				return fmt.Errorf("opening audit db: %w", err)
			}
			defer func() { _ = store.Close() }()

			res, err := store.DB().Exec(
				`DELETE FROM audit_log WHERE timestamp < ?`, cutoff.UTC().Format(time.RFC3339))
			if err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			n, _ := res.RowsAffected()
			fmt.Printf("deleted %d entries older than %s\n", n, cutoff.Format("2006-01-02"))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to audit db")
	cmd.Flags().StringVar(&before, "before", "", "cutoff date YYYY-MM-DD (exclusive)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the destructive delete")
	_ = cmd.MarkFlagRequired("before")
	return cmd
}

// parseCutoff accepts either YYYY-MM-DD or a full RFC3339 timestamp.
func parseCutoff(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("--before is required")
	}
	if len(s) == len("2006-01-02") && strings.Count(s, "-") == 2 {
		return time.ParseInLocation("2006-01-02", s, time.UTC)
	}
	return time.Parse(time.RFC3339, s)
}

// archivedEntry mirrors the audit_log columns in the JSONL export. Kept
// local to the CLI so external tooling has a stable schema regardless of
// internal.audit.Entry evolution.
type archivedEntry struct {
	ID                string `json:"id"`
	Timestamp         string `json:"timestamp"`
	FromAgent         string `json:"from_agent"`
	ToAgent           string `json:"to_agent"`
	ToolName          string `json:"tool_name,omitempty"`
	ContentHash       string `json:"content_hash"`
	SignatureVerified int    `json:"signature_verified"`
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
	Status            string `json:"status"`
	RulesTriggered    string `json:"rules_triggered,omitempty"`
	PolicyDecision    string `json:"policy_decision"`
	LatencyMs         int64  `json:"latency_ms"`
	Intent            string `json:"intent,omitempty"`
	SessionID         string `json:"session_id,omitempty"`
	PrevHash          string `json:"prev_hash,omitempty"`
	EntryHash         string `json:"entry_hash,omitempty"`
	ProxySignature    string `json:"proxy_signature,omitempty"`
}
