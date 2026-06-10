package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/netutil"
	"github.com/oktsec/oktsec/internal/policybundle"
	"github.com/oktsec/oktsec/internal/safefile"
	"github.com/spf13/cobra"
)

// maxPullObjectBytes caps every object the pull fetches (index, sig, bundle).
const maxPullObjectBytes = 1 << 20 // 1 MiB

// pullHTTPTimeout bounds an HTTPS fetch of a single store object.
const pullHTTPTimeout = 15 * time.Second

// newPolicyPullCmd builds `oktsec policy pull` (Order 9C). The node fetches a
// signed pull store from an operator-controlled source, verifies the index
// signature against its pinned trust fingerprint, selects the bundle for its
// target, and routes that bundle through the SAME verify + target-binding +
// anti-rollback + apply pipeline `policy apply` uses. Enterprise never contacts
// the node; the node initiates everything here.
func newPolicyPullCmd() *cobra.Command {
	var (
		source  string
		nodeID  string
		trustFP string
		dryRun  bool
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Fetch a signed policy bundle from an operator store and apply it locally",
		Long: "Fetch index.json + index.json.sig from --source (a local directory, a file:// " +
			"URL, or an https:// URL), verify the index signature against --trust-fingerprint, " +
			"select the bundle for --node-id (the node-scoped entry if present, else the fleet " +
			"entry), fetch it, and run the same verification + target binding + anti-rollback + " +
			"apply pipeline as `policy apply`. With --dry-run it writes nothing. The bundle's own " +
			"signature is the final authority; a signed index only decides which bundle to fetch.",
		Example: "  oktsec policy pull --source file:///srv/oktsec-store --node-id node_abc \\\n" +
			"    --trust-fingerprint sha256:<policy-key-fp> --config oktsec.yaml --dry-run --json",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if source == "" {
				return fmt.Errorf("--source <path-or-url> is required")
			}
			if trustFP == "" {
				return fmt.Errorf("--trust-fingerprint sha256:<fp> is required")
			}
			if nodeID == "" {
				return fmt.Errorf("--node-id <id> is required (selects this node's target and binds a node-scoped bundle)")
			}

			raw, res, _, found, perr := pullVerifiedBundle(source, nodeID, trustFP)
			_ = raw
			if perr != nil {
				if perr.verifyStage {
					return emitApplyFailure(cmd, jsonOut, dryRun, perr.err)
				}
				return perr.err
			}
			if !found {
				if jsonOut {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{
						"pulled": false, "source": source, "node_id": nodeID,
						"reason": "no_target_entry",
					})
				}
				fmt.Fprintf(cmd.OutOrStdout(), "no bundle to pull: the store index targets neither node %q nor the fleet\n", nodeID)
				return nil
			}
			_, err := runPolicyApplyV2(cmd, res.V2, nodeID, dryRun, jsonOut, false)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&source, "source", "", "pull store: a local directory, a file:// URL, or an https:// URL")
	f.StringVar(&nodeID, "node-id", "", "this node's id (selects its target entry; bound against the bundle's target)")
	f.StringVar(&trustFP, "trust-fingerprint", "", "sha256:<fp> the index and bundle signing key must match")
	f.BoolVar(&dryRun, "dry-run", false, "compute and print the projection without writing")
	f.BoolVar(&jsonOut, "json", false, "emit result as JSON")
	return cmd
}

// pullStageError distinguishes verification failures (which `policy
// pull --json` routes through emitApplyFailure for a structured JSON
// document) from plain fetch/transport failures.
type pullStageError struct {
	err         error
	verifyStage bool
}

func (e *pullStageError) Error() string { return e.err.Error() }
func (e *pullStageError) Unwrap() error { return e.err }

// pullVerifiedBundle is the SINGLE pull pipeline shared by
// `policy pull` and `cloud sync`: fetch index.json + signature, verify
// the index signature against the trust fingerprint, select nodeID's
// entry, fetch the named bundle from a store-contained path, verify it,
// and bind it to the signed entry. The ordering is part of the security
// contract: signature before parse, path check before fetch, bind
// before any apply. found=false means the store publishes nothing for
// this node (a clean no-op for callers).
func pullVerifiedBundle(source, nodeID, trustFP string) (raw []byte, res *policybundle.VerifyResult, entry policybundle.PullIndexEntry, found bool, perr *pullStageError) {
	fail := func(verify bool, err error) ([]byte, *policybundle.VerifyResult, policybundle.PullIndexEntry, bool, *pullStageError) {
		return nil, nil, policybundle.PullIndexEntry{}, false, &pullStageError{err: err, verifyStage: verify}
	}
	fetch, err := newStoreFetcher(source)
	if err != nil {
		return fail(false, fmt.Errorf("--source: %w", err))
	}

	// 1. Fetch + signature-verify the index BEFORE trusting any entry.
	indexBytes, err := fetch("index.json")
	if err != nil {
		return fail(false, fmt.Errorf("fetch index.json: %w", err))
	}
	sigBytes, err := fetch("index.json.sig")
	if err != nil {
		return fail(false, fmt.Errorf("fetch index.json.sig: %w", err))
	}
	if err := policybundle.VerifyPullIndexSig(indexBytes, sigBytes, trustFP); err != nil {
		return fail(true, err)
	}
	idx, err := policybundle.ParsePullIndex(indexBytes)
	if err != nil {
		return fail(true, err)
	}

	// 2. Select this node's target entry.
	entry, ok := policybundle.SelectPullEntry(idx, nodeID)
	if !ok {
		return nil, nil, policybundle.PullIndexEntry{}, false, nil
	}

	// 3. Fetch the selected bundle from a store-contained relative path.
	if err := safeStoreRelPath(entry.BundleFile); err != nil {
		return fail(false, fmt.Errorf("index bundle_file %q: %w", entry.BundleFile, err))
	}
	raw, err = fetch(entry.BundleFile)
	if err != nil {
		return fail(false, fmt.Errorf("fetch bundle %q: %w", entry.BundleFile, err))
	}

	// 4. The bundle is the authority: verify it, then bind it to the
	// SIGNED index entry. Without the binding, an attacker who can swap
	// the bundle file (but not the signed index) could serve a different
	// validly-signed bundle — e.g. an older one signed by the same key —
	// and a fresh node with no anti-rollback floor would apply it.
	res, verr := policybundle.Verify(raw, trustFP)
	if verr != nil {
		return fail(true, verr)
	}
	if err := bindPulledBundle(res, entry); err != nil {
		return fail(true, err)
	}
	return raw, res, entry, true, nil
}

// bindPulledBundle is the single source of the fetched-bundle-vs-signed-
// index-entry binding check, shared by `policy pull` and `cloud sync`:
// the verified bundle's hash and full assignment binding must equal the
// entry the SIGNED index named. v2-only is enforced here too.
func bindPulledBundle(res *policybundle.VerifyResult, entry policybundle.PullIndexEntry) error {
	if res.SchemaVersion != policybundle.SchemaVersionV2 {
		return fmt.Errorf("pull supports policy_bundle.v2 only; store bundle is %q", res.SchemaVersion)
	}
	a := res.V2.Bundle.Policy.Assignment
	if res.V2.Bundle.PolicyHash != entry.PolicyHash ||
		a.AssignmentID != entry.AssignmentID ||
		a.Sequence != entry.Sequence ||
		a.Target.Scope != entry.TargetScope ||
		a.Target.NodeID != entry.TargetNodeID {
		return fmt.Errorf("fetched bundle does not match the signed index entry "+
			"(index hash=%s seq=%d assignment=%s target=%s/%s; bundle hash=%s seq=%d assignment=%s target=%s/%s)",
			entry.PolicyHash, entry.Sequence, entry.AssignmentID, entry.TargetScope, entry.TargetNodeID,
			res.V2.Bundle.PolicyHash, a.Sequence, a.AssignmentID, a.Target.Scope, a.Target.NodeID)
	}
	return nil
}

// newStoreFetcher returns a function that reads a store object by its relative
// path. Local directories and file:// URLs read the filesystem through
// safefile (symlink-rejecting, size-capped); https:// URLs fetch over an
// SSRF-guarded client. http:// is allowed too (operator-chosen plaintext store)
// but runs through the same SSRF guard.
func newStoreFetcher(source string) (func(rel string) ([]byte, error), error) {
	// Only route RECOGNIZED URL schemes through the URL branch. Anything else —
	// no scheme, or a Windows drive path like `C:\store` that url.Parse reads as
	// scheme "c" — is a local filesystem path.
	if u, err := url.Parse(source); err == nil {
		switch u.Scheme {
		case "file":
			if u.Host != "" && u.Host != "localhost" {
				return nil, fmt.Errorf("file:// URL must be local (no host), got host %q", u.Host)
			}
			return localFetcher(u.Path), nil
		case "http", "https":
			return httpFetcher(source), nil
		}
	}
	return localFetcher(source), nil
}

func localFetcher(root string) func(rel string) ([]byte, error) {
	return func(rel string) ([]byte, error) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := safefile.RejectSymlink(p); err != nil {
			return nil, err
		}
		return safefile.ReadFileMax(p, maxPullObjectBytes)
	}
}

// pullDialContext is the dialer the HTTPS store fetcher uses. It defaults to the
// SSRF-guarded dialer (blocks loopback, link-local, and cloud metadata IPs);
// tests override it to reach a local test server, which the guard would
// otherwise (correctly) refuse.
var pullDialContext = netutil.SafeDialContext

func httpFetcher(base string) func(rel string) ([]byte, error) {
	client := &http.Client{
		Timeout:   pullHTTPTimeout,
		Transport: &http.Transport{DialContext: pullDialContext},
	}
	return func(rel string) ([]byte, error) {
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		// Join the relative object onto the base URL path without letting it
		// escape the base (path.Join cleans, and safeStoreRelPath already
		// rejected traversal for the bundle path).
		u.Path = path.Join(u.Path, rel)
		ctx, cancel := context.WithTimeout(context.Background(), pullHTTPTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s -> %d", rel, resp.StatusCode)
		}
		// Read one byte past the cap so an over-large object is REJECTED (the
		// local read path already errors past the cap); silently verifying a
		// truncated prefix of the served bytes would be wrong.
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPullObjectBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > maxPullObjectBytes {
			return nil, fmt.Errorf("object %s exceeds %d bytes", rel, maxPullObjectBytes)
		}
		return body, nil
	}
}

// safeStoreRelPath rejects a bundle_file path that is absolute or escapes the
// store root, so a tampered index cannot redirect the fetch outside the store.
func safeStoreRelPath(rel string) error {
	if rel == "" {
		return fmt.Errorf("empty path")
	}
	if strings.ContainsRune(rel, '\\') {
		return fmt.Errorf("backslash not allowed")
	}
	if path.IsAbs(rel) || strings.HasPrefix(rel, "/") {
		return fmt.Errorf("must be relative")
	}
	cleaned := path.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != rel {
		return fmt.Errorf("must be a clean relative path with no traversal")
	}
	return nil
}
