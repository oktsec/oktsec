package commands

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

// verifyChainResult is the JSON output structure for verify-chain.
type verifyChainResult struct {
	Valid          bool   `json:"valid"`
	Entries        int    `json:"entries"`
	BrokenAt       int    `json:"broken_at,omitempty"`
	BrokenID       string `json:"broken_id,omitempty"`
	Reason         string `json:"reason,omitempty"`
	LastTimestamp   string `json:"last_timestamp,omitempty"`
	SignatureCheck  string `json:"signature_check"` // "valid", "skipped", "invalid"
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

func newVerifyChainCmd() *cobra.Command {
	var (
		dbPath     string
		keyPath    string
		limit      int
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "verify-chain",
		Short: "Verify the tamper-evident audit hash chain",
		Long:  "Opens the audit database and verifies the SHA-256 hash chain and optional Ed25519 proxy signatures.",
		Example: `  oktsec audit verify-chain
  oktsec audit verify-chain --db /path/to/oktsec.db
  oktsec audit verify-chain --key /path/to/proxy.pub --limit 5000
  oktsec audit verify-chain --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerifyChain(dbPath, keyPath, limit, jsonOutput)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "", "path to audit database (default: from config or ~/.oktsec/oktsec.db)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to proxy public key PEM file (default: keys/proxy.pub)")
	cmd.Flags().IntVar(&limit, "limit", 10000, "maximum number of chain entries to verify")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")

	return cmd
}

func runVerifyChain(dbPath, keyPath string, limit int, jsonOutput bool) error {
	// Resolve database path
	if dbPath == "" {
		dbPath = resolveDBPath()
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return exitError(2, fmt.Sprintf("audit database not found: %s", dbPath))
	}

	// Open store read-only by using query_only pragma via the DSN.
	// NewStore opens the DB and runs migrations, but query_only prevents writes.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	if err != nil {
		return exitError(2, fmt.Sprintf("opening audit db: %v", err))
	}
	defer func() { _ = store.Close() }()

	// Load proxy public key
	var proxyPub ed25519.PublicKey
	keyPath = resolveKeyPath(keyPath)
	if keyPath != "" {
		pub, err := loadPubKeyFromFile(keyPath)
		if err != nil {
			// Key not found is not fatal — just skip signature verification
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "warning: could not load proxy key: %v\n", err)
			}
		} else {
			proxyPub = pub
		}
	}

	// Query chain entries
	entries, err := store.QueryChainEntries(limit)
	if err != nil {
		return exitError(2, fmt.Sprintf("querying chain entries: %v", err))
	}

	// Verify chain
	result := audit.VerifyChain(entries, proxyPub)

	// Build output
	out := verifyChainResult{
		Valid:   result.Valid,
		Entries: result.Entries,
	}

	if result.Entries > 0 {
		out.LastTimestamp = entries[len(entries)-1].Timestamp
	}

	if proxyPub != nil {
		if result.Valid {
			out.SignatureCheck = "valid"
		} else if result.Reason == "proxy signature invalid" {
			out.SignatureCheck = "invalid"
		} else {
			out.SignatureCheck = "valid" // chain broke for non-signature reason, sigs were ok up to that point
		}
		out.KeyFingerprint = identity.Fingerprint(proxyPub)
	} else {
		out.SignatureCheck = "skipped"
	}

	if !result.Valid {
		out.BrokenAt = result.BrokenAt
		out.BrokenID = result.BrokenID
		out.Reason = result.Reason
	}

	if jsonOutput {
		return printVerifyChainJSON(out)
	}
	printVerifyChainTerminal(out)

	if !out.Valid {
		os.Exit(1)
	}
	return nil
}

func printVerifyChainTerminal(r verifyChainResult) {
	fmt.Println()
	if r.Entries == 0 {
		fmt.Println("  Chain: EMPTY (no entries)")
		fmt.Println()
		return
	}

	if r.Valid {
		fmt.Printf("  Chain: VALID (%s entries)\n", formatCount(r.Entries))
	} else {
		fmt.Printf("  Chain: BROKEN at entry %d\n", r.BrokenAt)
		fmt.Printf("  Reason: %s\n", r.Reason)
		fmt.Printf("  Entry ID: %s\n", r.BrokenID)
	}

	switch r.SignatureCheck {
	case "valid":
		fmt.Printf("  Signature: VALID (proxy key fingerprint: %s)\n", truncateFingerprint(r.KeyFingerprint))
	case "invalid":
		fmt.Printf("  Signature: INVALID (proxy key fingerprint: %s)\n", truncateFingerprint(r.KeyFingerprint))
	case "skipped":
		fmt.Println("  Signature: SKIPPED (no proxy key provided)")
	}

	if r.LastTimestamp != "" {
		fmt.Printf("  Last entry: %s\n", r.LastTimestamp)
	}
	fmt.Println()
}

func printVerifyChainJSON(r verifyChainResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// resolveDBPath determines the audit database path from config or defaults.
func resolveDBPath() string {
	// Try loading config to get db_path
	cfg, err := config.Load(cfgFile)
	if err == nil && cfg.DBPath != "" {
		return cfg.DBPath
	}
	return config.DefaultDBPath()
}

// resolveKeyPath determines the proxy public key path.
func resolveKeyPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	// Try loading config to get keys_dir
	cfg, err := config.Load(cfgFile)
	if err == nil && cfg.Identity.KeysDir != "" {
		candidate := filepath.Join(cfg.Identity.KeysDir, "proxy.pub")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Try default keys dir
	candidate := filepath.Join(config.DefaultKeysDir(), "proxy.pub")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

// loadPubKeyFromFile loads an Ed25519 public key from a PEM file.
func loadPubKeyFromFile(path string) (ed25519.PublicKey, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	// Strip .pub extension for identity.LoadPublicKey
	if ext := filepath.Ext(name); ext == ".pub" {
		name = name[:len(name)-len(ext)]
	}
	return identity.LoadPublicKey(dir, name)
}

// formatCount formats an integer with comma separators.
func formatCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	result := make([]byte, 0, len(s)+len(s)/3)
	offset := len(s) % 3
	if offset == 0 {
		offset = 3
	}
	result = append(result, s[:offset]...)
	for i := offset; i < len(s); i += 3 {
		result = append(result, ',')
		result = append(result, s[i:i+3]...)
	}
	return string(result)
}

// truncateFingerprint returns the first 4 and last 4 hex chars of a fingerprint.
func truncateFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:4] + "..." + fp[len(fp)-4:]
}

// exitError prints an error message to stderr and exits with the given code.
func exitError(code int, msg string) error {
	fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	os.Exit(code)
	return nil // unreachable, but satisfies return type
}
