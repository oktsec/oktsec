package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/node"
	"github.com/spf13/cobra"
)

// newNodeCmd builds the `oktsec node` command group. Order 1 shipped
// init / status / snapshot; Phase 5 Order 3A adds sign-snapshot for
// producing signed envelopes that downstream consumers (e.g.
// `oktsec-enterprise ingest`) can verify against the local node key.
// All subcommands are local-only and read-only with respect to the
// Oktsec runtime — none of them open a network socket or modify
// running enforcement.
func newNodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Manage the local Oktsec node identity, snapshot, and signed envelopes",
		Long: "Node commands manage this Oktsec install as a single protected runtime node. " +
			"Identity is local-only; snapshot is read-only and reports what this node sees, " +
			"controls, and can prove. sign-snapshot wraps a snapshot in a signed envelope so " +
			"downstream consumers can verify it came from this node's identity without " +
			"exposing the private key.",
	}
	cmd.AddCommand(newNodeInitCmd())
	cmd.AddCommand(newNodeStatusCmd())
	cmd.AddCommand(newNodeSnapshotCmd())
	cmd.AddCommand(newNodeSignSnapshotCmd())
	return cmd
}

// newNodeInitCmd creates or confirms the local node identity.
func newNodeInitCmd() *cobra.Command {
	var (
		profile    string
		jsonOutput bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the local node identity (idempotent)",
		Example: "  oktsec node init\n" +
			"  oktsec node init --profile enterprise\n" +
			"  oktsec node init --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := nodeStoreForTest()
			id, err := store.Init(profile)
			if err != nil {
				return fmt.Errorf("init node identity: %w", err)
			}
			out := cmd.OutOrStdout()
			if jsonOutput {
				return writeIndentedJSON(out, node.IdentityStatus{
					Status:   "present",
					Identity: id,
				})
			}
			fmt.Fprintf(out, "Node identity ready\n")
			fmt.Fprintf(out, "  node_id:        %s\n", id.NodeID)
			fmt.Fprintf(out, "  fingerprint:    %s\n", truncateNodeFingerprint(id.PublicKeyFingerprint))
			fmt.Fprintf(out, "  profile:        %s\n", id.InstallProfile)
			fmt.Fprintf(out, "  directory:      %s\n", store.Dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "local", "install profile: local | enterprise")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	return cmd
}

// newNodeStatusCmd reports identity presence without modifying it.
func newNodeStatusCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show local node identity status",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := nodeStoreForTest()
			status := store.Status()
			out := cmd.OutOrStdout()
			if jsonOutput {
				if err := writeIndentedJSON(out, status); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(out, "Node identity: %s\n", status.Status)
				if status.Identity != nil {
					fmt.Fprintf(out, "  node_id:      %s\n", status.Identity.NodeID)
					fmt.Fprintf(out, "  fingerprint:  %s\n", truncateNodeFingerprint(status.Identity.PublicKeyFingerprint))
					fmt.Fprintf(out, "  profile:      %s\n", status.Identity.InstallProfile)
					fmt.Fprintf(out, "  created_at:   %s\n", status.Identity.CreatedAt)
				}
				for _, w := range status.Warnings {
					fmt.Fprintf(out, "  warning [%s]: %s\n", w.Code, w.Message)
				}
			}
			if status.Status == "invalid" {
				return errInvalidNodeIdentity
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	return cmd
}

// newNodeSnapshotCmd produces a read-only JSON snapshot of what this
// node sees, controls, and can prove.
func newNodeSnapshotCmd() *cobra.Command {
	var (
		since            string
		until            string
		outputPath       string
		jsonOutput       bool
		includeDiscovery bool
		policyBundle     string
	)
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Emit a read-only snapshot of this node's coverage and evidence",
		Long: "Reports configured surfaces, inventory, posture, and audit evidence as JSON. " +
			"Read-only: no databases are created, no migrations run, no external clients are touched.",
		Example: "  oktsec node snapshot --json\n" +
			"  oktsec node snapshot --since 24h --output /tmp/node.json\n" +
			"  oktsec node snapshot --policy-bundle /etc/oktsec/policy.signed.json --json\n" +
			"  oktsec node snapshot --since 2026-05-20T00:00:00Z --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			sinceT, err := parseSnapshotSince(since)
			if err != nil {
				return err
			}
			untilT, err := parseSnapshotUntil(until)
			if err != nil {
				return err
			}
			opts := node.Options{
				ConfigPath:       cfgFile,
				DBPath:           nodeSnapshotDBPathOverride,
				IdentityStore:    nodeStoreForTest(),
				Since:            sinceT,
				Until:            untilT,
				IncludeDiscovery: includeDiscovery,
				PolicyBundlePath: policyBundle,
				OktsecVersion:    version,
				OktsecCommit:     commit,
			}
			snap, err := node.Build(context.Background(), opts)
			if err != nil {
				return fmt.Errorf("building snapshot: %w", err)
			}
			data, err := node.MarshalSnapshot(snap)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if outputPath != "" {
				if err := writeSnapshotFile(outputPath, data); err != nil {
					return err
				}
				if !jsonOutput {
					fmt.Fprintf(out, "Wrote node snapshot to %s\n", outputPath)
				}
				return nil
			}
			if _, err := out.Write(data); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "snapshot range floor (Go duration or RFC3339)")
	cmd.Flags().StringVar(&until, "until", "", "snapshot range ceiling (RFC3339; default: now)")
	cmd.Flags().StringVar(&outputPath, "output", "", "write snapshot to this path instead of stdout")
	cmd.Flags().BoolVar(&jsonOutput, "json", true, "emit JSON (always true in Order 1)")
	cmd.Flags().BoolVar(&includeDiscovery, "include-discovery", false, "request MCP client discovery (Order 1: not supported, warns)")
	cmd.Flags().StringVar(&policyBundle, "policy-bundle", "", "path to a local signed policy bundle to report as this node's active policy (declarative only; not verified or applied)")
	return cmd
}

// parseSnapshotSince accepts a Go duration (e.g. "24h") or an
// RFC3339 timestamp. The duration form is the common case; absolute
// timestamps let operators pin a snapshot to a known event window.
func parseSnapshotSince(in string) (time.Time, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(in); err == nil {
		if d < 0 {
			d = -d
		}
		return time.Now().UTC().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, in); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("--since must be a Go duration (e.g. 24h) or RFC3339 timestamp")
}

// parseSnapshotUntil accepts only RFC3339 (and empty = now). Duration
// would be ambiguous here ("24h ago" vs "24h from now") so it's not
// supported.
func parseSnapshotUntil(in string) (time.Time, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, in)
	if err != nil {
		return time.Time{}, fmt.Errorf("--until must be RFC3339")
	}
	return t.UTC(), nil
}

// writeSnapshotFile writes data atomically to path, refusing to
// follow symlinks at the destination so a malicious link in
// /tmp/node.json cannot redirect the write elsewhere.
func writeSnapshotFile(path string, data []byte) error {
	if path == "" {
		return errors.New("--output path is required")
	}
	// Reject symlinked destination so a planted symlink cannot
	// be used to overwrite an unrelated file.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through a symlink: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat output path: %w", err)
	}
	// Reject symlinked parent for the same reason.
	parent := filepath.Dir(path)
	if info, err := os.Lstat(parent); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write into a symlinked directory: %s", parent)
		}
	}
	tmp, err := os.CreateTemp(parent, ".node-snapshot-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false
	return nil
}

// writeIndentedJSON renders v as indented JSON to w.
func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// errInvalidNodeIdentity is returned by `node status` when the on-disk
// identity exists but cannot be parsed. Cobra surfaces it as a
// non-zero exit code, matching the spec's exit contract.
var errInvalidNodeIdentity = errors.New("node identity is invalid")

// truncateNodeFingerprint shrinks a "sha256:<hex>" fingerprint for
// terminal display while keeping enough characters to be useful for
// confirmation.
func truncateNodeFingerprint(fp string) string {
	if fp == "" {
		return "(none)"
	}
	hex := fp
	if i := strings.Index(fp, ":"); i >= 0 {
		hex = fp[i+1:]
	}
	if len(hex) <= 12 {
		return fp
	}
	prefix := ""
	if i := strings.Index(fp, ":"); i >= 0 {
		prefix = fp[:i+1]
	}
	return prefix + hex[:8] + "…" + hex[len(hex)-4:]
}

// nodeStoreForTest is a hook tests use to override the default
// identity directory without rerouting config.HomeDir() (which is
// cached via sync.Once and cannot be reset). Production code never
// touches it.
var nodeStoreForTest = func() node.IdentityStore { return node.DefaultIdentityStore() }

// nodeSnapshotDBPathOverride pins the DB path used by the snapshot
// command. Empty (the default) lets node.Build resolve via config
// and the default home. Tests set this to a temp path so they
// never reach the developer's real audit DB.
var nodeSnapshotDBPathOverride string
