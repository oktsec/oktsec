package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/oktsec/oktsec/internal/node"
	"github.com/oktsec/oktsec/internal/safefile"
	"github.com/spf13/cobra"
)

// maxSnapshotFileBytes mirrors the 4 MiB cap node.snapshot.go uses
// for its own --output path. Anything larger almost certainly is
// not a snapshot, so we refuse it pre-parse to keep the signing
// path's memory footprint bounded.
const maxSnapshotFileBytes = 4 * 1024 * 1024

// newNodeSignSnapshotCmd wraps a redacted node_snapshot.v1 JSON file
// in a signed envelope (node_snapshot_envelope.v1). The private key
// never leaves ~/.oktsec/node/node.key; the envelope embeds the
// public key in raw base64 so downstream verifiers can check the
// signature without consulting the node again.
func newNodeSignSnapshotCmd() *cobra.Command {
	var (
		snapshotPath string
		outputPath   string
	)
	cmd := &cobra.Command{
		Use:   "sign-snapshot",
		Short: "Wrap a redacted node_snapshot.v1 file in a signed envelope",
		Long: "Reads a snapshot file produced by `oktsec node snapshot --json`, " +
			"validates that it belongs to this node's identity, canonicalizes it, " +
			"signs the domain-separated payload with the local node Ed25519 key, " +
			"and emits a node_snapshot_envelope.v1 JSON object. The original " +
			"snapshot is embedded verbatim. No data leaves this machine.",
		Example: "  oktsec node snapshot --json --output /tmp/snap.json\n" +
			"  oktsec node sign-snapshot --snapshot /tmp/snap.json --output /tmp/snap.envelope.json\n" +
			"  oktsec node sign-snapshot --snapshot /tmp/snap.json\n" +
			"  cat /tmp/snap.json | oktsec node sign-snapshot --snapshot -",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := readSnapshotInput(snapshotPath)
			if err != nil {
				return err
			}
			snap, err := decodeSnapshotStrict(raw)
			if err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}
			env, err := node.SealSnapshotEnvelope(nodeStoreForTest(), snap, time.Now())
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(env, "", "  ")
			if err != nil {
				return fmt.Errorf("encode envelope: %w", err)
			}
			out = append(out, '\n')
			if outputPath != "" {
				return writeSnapshotFile(outputPath, out)
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "",
		"path to a node_snapshot.v1 JSON file, or '-' for stdin (required)")
	cmd.Flags().StringVar(&outputPath, "output", "",
		"write the signed envelope here (default: stdout)")
	_ = cmd.MarkFlagRequired("snapshot")
	return cmd
}

// readSnapshotInput pulls bytes from a file path or stdin under the
// 4 MiB cap. The file path goes through safefile.ReadFileMax so a
// symlinked input is refused atomically (no TOCTOU window between
// stat and read). Stdin has no symlink concern but still respects
// the size cap.
func readSnapshotInput(path string) ([]byte, error) {
	switch path {
	case "":
		return nil, errors.New("--snapshot is required (use '-' for stdin)")
	case "-":
		body, err := io.ReadAll(io.LimitReader(os.Stdin, maxSnapshotFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if int64(len(body)) > maxSnapshotFileBytes {
			return nil, fmt.Errorf("stdin snapshot exceeds %d bytes", maxSnapshotFileBytes)
		}
		return body, nil
	default:
		body, err := safefile.ReadFileMax(path, maxSnapshotFileBytes)
		if err != nil {
			return nil, fmt.Errorf("read snapshot: %w", err)
		}
		return body, nil
	}
}

// decodeSnapshotStrict parses raw into a node.Snapshot using a
// decoder that refuses unknown fields AND refuses trailing JSON
// content. Strictness here closes two distinct flavors of the
// "signed subset" gap:
//
//   - unknown fields would be silently dropped by the typed-struct
//     decoder, so the envelope would sign a smaller artifact than
//     the operator handed us;
//   - trailing JSON tokens after the first object would be lost
//     completely. A file like
//     { "schema_version": "node_snapshot.v1", ... }
//     { "extra": "not signed" }
//     decodes the first object cleanly under DisallowUnknownFields,
//     and without the EOF check we would happily sign that first
//     object and discard the second. Same threat model, different
//     vector — so both gates live here.
//
// schema_version is also enforced explicitly rather than left to
// the JSON Schema validator, because this command does not depend
// on the JSON Schema files at runtime.
func decodeSnapshotStrict(raw []byte) (node.Snapshot, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s node.Snapshot
	if err := dec.Decode(&s); err != nil {
		return node.Snapshot{}, fmt.Errorf("strict decode: %w", err)
	}
	// Refuse trailing tokens. Decoding into a throwaway value with
	// the same decoder reads the next JSON value; anything other
	// than io.EOF means the input contained more than a single
	// snapshot object and the rest would be silently dropped if
	// signing went ahead.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return node.Snapshot{}, fmt.Errorf("strict decode: trailing JSON content after snapshot object")
		}
		return node.Snapshot{}, fmt.Errorf("strict decode: trailing content not parseable: %w", err)
	}
	if s.SchemaVersion != node.SchemaSnapshot {
		return node.Snapshot{}, fmt.Errorf("schema_version %q is not %q", s.SchemaVersion, node.SchemaSnapshot)
	}
	return s, nil
}
