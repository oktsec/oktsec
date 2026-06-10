package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oktsec/oktsec/internal/netutil"
	"github.com/oktsec/oktsec/internal/node"
	"github.com/spf13/cobra"
)

// `oktsec cloud` connects this node to an Oktsec Cloud control plane.
// The trust model is the node's, unchanged: the node INITIATES every
// exchange (register, report, pull); Cloud never reaches in. Apply runs
// through the exact same verify + target-binding + anti-rollback
// pipeline as `policy apply` / `policy pull` — these commands only
// orchestrate steps that already exist.
//
// State lives beside the node identity (0600):
//
//	cloud.json   — url, pull store URL, trust fingerprint, sync stamps
//	cloud-token  — the node's bearer token (secret; never printed)

const cloudHTTPTimeout = 30 * time.Second

// cloudDialContext is the dialer for Cloud API calls. SSRF-guarded by
// default (loopback, link-local and metadata IPs refused); tests
// override it to reach a local test server.
var cloudDialContext = netutil.SafeDialContext

// cloudMinInterval keeps daemon mode polite (Cloud rate limits are
// generous, but a sub-minute loop is never needed).
const cloudMinInterval = time.Minute

// cloudApplyDevDialEscape relaxes the SSRF dial guard for the running
// `cloud` command when OKTSEC_CLOUD_INSECURE_HTTP=1 — the same
// dev-only escape that admits a plaintext --url. A local or LAN test
// Cloud sits in address ranges the guard refuses by design, so the
// escape that already declares "this is a development environment"
// covers both relaxations. It mutates the dial seams of THIS process
// only, from `cloud` entry points only: `policy pull` invocations and
// every server-side surface keep the hard guard regardless of
// environment.
func cloudApplyDevDialEscape() {
	if os.Getenv("OKTSEC_CLOUD_INSECURE_HTTP") != "1" {
		return
	}
	plain := (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	cloudDialContext = plain
	pullDialContext = plain
}

// cloudHTTPClient builds the SSRF-guarded client for Cloud API calls.
// Daemon mode constructs it ONCE per run (keep-alive across ticks);
// the seam stays a var so tests can point it at a local server.
func cloudHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   cloudHTTPTimeout,
		Transport: &http.Transport{DialContext: cloudDialContext},
	}
}

// cloudPost sends JSON with a bearer token and decodes the JSON reply.
// The response body is returned for error detail; bearer secrets never
// appear in errors.
func cloudPost(client *http.Client, rawURL, bearer string, body []byte) (int, map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	out := map[string]any{}
	if len(raw) > 0 {
		// Tolerate non-JSON error bodies; the status code still tells
		// the caller what happened.
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out, nil
}

func newCloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Connect this node to an Oktsec Cloud control plane",
		Long: "Enroll this node with Oktsec Cloud, then keep it in sync: report signed " +
			"evidence and pull + verify + apply the signed policy published for it. The node " +
			"initiates everything; Cloud has no way to reach in.",
	}
	cmd.AddCommand(newCloudEnrollCmd(), newCloudSyncCmd(), newCloudStatusCmd())
	return cmd
}

// --- enroll -----------------------------------------------------------

func newCloudEnrollCmd() *cobra.Command {
	var (
		cloudURL string
		token    string
		pullURL  string
		trustFP  string
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Register this node with Oktsec Cloud",
		Long: "Registers this node's identity with Cloud using an enrollment token and stores " +
			"the connection state beside the node identity. The pull store URL and policy trust " +
			"fingerprint are taken from Cloud's response when available, or from flags.",
		Example:      "  oktsec cloud enroll --url https://cloud.oktsec.com --token <enrollment-token>",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cloudURL == "" || token == "" {
				return fmt.Errorf("--url and --token are required")
			}
			cloudApplyDevDialEscape()
			base, err := normalizeCloudURL(cloudURL)
			if err != nil {
				return err
			}
			store := nodeStoreForTest()
			id, err := store.Load()
			if err != nil {
				if node.IsErrIdentityMissing(err) {
					return fmt.Errorf("no node identity yet — run `oktsec node init` first")
				}
				return err
			}

			payload, err := json.Marshal(map[string]string{
				"node_id":                id.NodeID,
				"public_key_fingerprint": id.PublicKeyFingerprint,
			})
			if err != nil {
				return err
			}
			client := cloudHTTPClient()
			status, body, err := cloudPost(client, base+"/v1/node/register", token, payload)
			if err != nil {
				return fmt.Errorf("register with %s: %w", base, err)
			}
			switch status {
			case http.StatusCreated:
				nodeToken, _ := body["token"].(string)
				if nodeToken == "" {
					return fmt.Errorf("register succeeded but no node token was returned")
				}
				if err := store.SaveCloudToken(nodeToken); err != nil {
					return err
				}
			case http.StatusOK:
				// Idempotent re-register: no new token. Keep the stored one.
				if _, err := store.LoadCloudToken(); err != nil {
					return fmt.Errorf("node already registered but no local token is stored — rotate it from Cloud and re-enroll: %w", err)
				}
			case http.StatusUnauthorized:
				return fmt.Errorf("enrollment token rejected (expired or revoked)")
			case http.StatusConflict:
				return fmt.Errorf("registration conflicts with Cloud's state for this node (identity pin mismatch)")
			default:
				return fmt.Errorf("register failed: HTTP %d", status)
			}

			// Merge, never wipe: explicit flags win, then Cloud's
			// register response, then whatever a previous enroll
			// stored — so an idempotent re-enroll without --pull-url
			// cannot silently disable policy pulls.
			prev, _ := store.LoadCloudState() // nil on first enroll
			if trustFP == "" {
				trustFP, _ = body["trust_fingerprint"].(string)
			}
			if pullURL == "" {
				pullURL, _ = body["pull_url"].(string)
			}
			enrolledAt := time.Now().UTC().Format(time.RFC3339)
			// Previous settings are only trustworthy for the SAME
			// control plane: carrying the old Cloud's pull capability
			// and trust anchor into an enrollment against a different
			// URL would leave the node reporting to one Cloud while
			// applying the other's policy.
			if prev != nil && prev.URL == base {
				if trustFP == "" {
					trustFP = prev.TrustFingerprint
				}
				if pullURL == "" {
					pullURL = prev.PullURL
				}
				enrolledAt = prev.EnrolledAt
			}
			st := &node.CloudState{
				URL:              base,
				PullURL:          pullURL,
				TrustFingerprint: trustFP,
				EnrolledAt:       enrolledAt,
			}
			if err := store.SaveCloudState(st); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Enrolled node %s with %s\n", id.NodeID, base)
			switch {
			case st.PullURL == "":
				fmt.Fprintln(out, "No pull store URL configured yet: `cloud sync` will report evidence only.")
				fmt.Fprintln(out, "Add it with: oktsec cloud enroll --url ... --token ... --pull-url <capability URL>")
			case st.TrustFingerprint == "":
				fmt.Fprintln(out, "No policy trust fingerprint yet: pulls stay disabled until one is set (--trust-fingerprint).")
			default:
				fmt.Fprintln(out, "Policy pull configured. Run: oktsec cloud sync --interval 5m")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cloudURL, "url", "", "Cloud base URL (https://cloud.example.com)")
	f.StringVar(&token, "token", "", "enrollment token issued by Cloud (shown once at creation)")
	f.StringVar(&pullURL, "pull-url", "", "this fleet's pull store URL (from the Cloud console)")
	f.StringVar(&trustFP, "trust-fingerprint", "", "policy signing trust fingerprint sha256:<hex> (defaults to Cloud's answer)")
	return cmd
}

func normalizeCloudURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("--url must be an http(s) base URL, got %q", raw)
	}
	// Bearer tokens travel in every Cloud call: plaintext HTTP would
	// leak them to any on-path network. https only, with an explicit
	// dev-only escape for local test servers.
	if u.Scheme == "http" && os.Getenv("OKTSEC_CLOUD_INSECURE_HTTP") != "1" {
		return "", fmt.Errorf("--url must be https (set OKTSEC_CLOUD_INSECURE_HTTP=1 only for local development)")
	}
	return u.String(), nil
}

// --- sync -------------------------------------------------------------

func newCloudSyncCmd() *cobra.Command {
	var (
		once     bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pull + apply published policy, then report signed evidence",
		Long: "One full cycle: fetch the signed pull store (when configured), verify and apply " +
			"the bundle published for this node through the standard pipeline, then build, sign " +
			"and report a snapshot so the evidence reflects the post-apply state. --interval runs " +
			"the cycle continuously; --once runs it a single time with distinct exit codes " +
			"(2 = pull/apply failed, 3 = evidence report failed).",
		Example: "  oktsec cloud sync --once --config oktsec.yaml\n" +
			"  oktsec cloud sync --interval 5m --config oktsec.yaml",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if once == (interval != 0) {
				return fmt.Errorf("pass exactly one of --once or --interval")
			}
			cloudApplyDevDialEscape()
			store := nodeStoreForTest()
			client := cloudHTTPClient()
			if once {
				return runCloudSyncOnce(cmd, store, client)
			}
			if interval < cloudMinInterval {
				return fmt.Errorf("--interval must be at least %s", cloudMinInterval)
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			out := cmd.ErrOrStderr()
			fmt.Fprintf(out, "cloud sync: every %s (±10%% jitter); SIGTERM to stop\n", interval)
			for {
				if err := runCloudSyncOnce(cmd, store, client); err != nil {
					fmt.Fprintf(out, "cloud sync: %v\n", err)
				}
				jitter := time.Duration(rand.Int63n(int64(interval) / 5))
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(interval - interval/10 + jitter):
				}
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&once, "once", false, "run one sync cycle and exit")
	f.DurationVar(&interval, "interval", 0, "run continuously with this period (min 1m)")
	return cmd
}

// cloudSyncError tags a sync failure with its --once exit code
// (2 = pull/apply, 3 = evidence report), surfaced via ExitCode so
// main can map it for systemd-style operators.
type cloudSyncError struct {
	stage string
	code  int
	err   error
}

func (e *cloudSyncError) Error() string { return e.stage + ": " + e.err.Error() }
func (e *cloudSyncError) Unwrap() error { return e.err }

// CommandExitCode lets main map sync failures to distinct process
// exit codes. Deliberately NOT named ExitCode: os/exec.ExitError has
// that method, and wrapped subprocess errors must not leak a child's
// exit code as ours.
func (e *cloudSyncError) CommandExitCode() int { return e.code }

// stampSync records the cycle result in cloud.json (best effort on
// failure paths; the ok path surfaces the write error).
func stampSync(store node.IdentityStore, st *node.CloudState, result string) error {
	st.LastSyncAt = time.Now().UTC().Format(time.RFC3339)
	st.LastSyncResult = result
	return store.SaveCloudState(st)
}

func runCloudSyncOnce(cmd *cobra.Command, store node.IdentityStore, client *http.Client) error {
	st, err := store.LoadCloudState()
	if err != nil {
		return err
	}
	token, err := store.LoadCloudToken()
	if err != nil {
		return err
	}
	id, err := store.Load()
	if err != nil {
		return err
	}

	// 1. Pull + apply FIRST so the snapshot reports post-apply state.
	// Real apply mutates the config, so the same explicit---config rule
	// as `policy apply`/`policy pull` holds.
	if st.PullURL != "" && st.TrustFingerprint != "" {
		if !cfgFileExplicit {
			return &cloudSyncError{stage: "pull/apply", code: 2,
				err: fmt.Errorf("policy pull is configured: pass an explicit --config <path> (the file the applied policy mutates)")}
		}
		if err := cloudPullApply(cmd, store, st, id.NodeID); err != nil {
			_ = stampSync(store, st, "pull_failed")
			return &cloudSyncError{stage: "pull/apply", code: 2, err: err}
		}
	}

	// 2. Snapshot reflecting the (possibly just-applied) active policy.
	opts := node.Options{
		ConfigPath:    cfgFile,
		DBPath:        nodeSnapshotDBPathOverride,
		IdentityStore: store,
		OktsecVersion: version,
		OktsecCommit:  commit,
	}
	if _, err := os.Stat(store.CloudBundlePath()); err == nil {
		opts.PolicyBundlePath = store.CloudBundlePath()
		opts.PolicyTrustFingerprint = st.TrustFingerprint
	}
	snap, err := node.Build(context.Background(), opts)
	if err != nil {
		return &cloudSyncError{stage: "snapshot", code: 3, err: err}
	}
	env, err := node.SealSnapshotEnvelope(store, snap, time.Now().UTC())
	if err != nil {
		return &cloudSyncError{stage: "sign", code: 3, err: err}
	}
	envRaw, err := json.Marshal(env)
	if err != nil {
		return &cloudSyncError{stage: "sign", code: 3, err: err}
	}

	// 3. Report.
	status, body, err := cloudPost(client, st.URL+"/v1/evidence/envelope", token, envRaw)
	if err != nil {
		return &cloudSyncError{stage: "report", code: 3, err: err}
	}
	result, _ := body["status"].(string)
	switch result {
	case "accepted", "accepted_signed", "idempotent":
		if err := stampSync(store, st, "ok"); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "sync ok (evidence %s)\n", result)
		return nil
	default:
		_ = stampSync(store, st, "report_failed")
		code, _ := body["code"].(string)
		if code == "" {
			code = fmt.Sprintf("http_%d", status)
		}
		return &cloudSyncError{stage: "report", code: 3, err: fmt.Errorf("evidence refused (%s)", code)}
	}
}

// cloudPullApply runs the SHARED pull pipeline (pullVerifiedBundle:
// signed index -> entry -> bundle -> binding) and applies through the
// standard v2 pipeline. The verified bundle bytes are cached so
// snapshots echo the active policy. A store with no entry for this
// node is a clean no-op.
func cloudPullApply(cmd *cobra.Command, store node.IdentityStore, st *node.CloudState, nodeID string) error {
	raw, res, entry, found, perr := pullVerifiedBundle(st.PullURL, nodeID, st.TrustFingerprint)
	if perr != nil {
		return perr.err
	}
	if !found {
		return nil // nothing published for this node yet
	}

	// Apply via the standard pipeline; output stays quiet (a no-op
	// apply is healthy), the structured outcome says what happened.
	applyCmd := &cobra.Command{}
	applyCmd.SetOut(io.Discard)
	applyCmd.SetErr(io.Discard)
	applied, err := runPolicyApplyV2(applyCmd, res.V2, nodeID, false, true, false)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	if applied {
		fmt.Fprintf(cmd.OutOrStdout(), "applied policy %s (sequence %d)\n", entry.PolicyID, entry.Sequence)
	}

	// Cache the verified bundle bytes for snapshot echoing.
	return store.SaveCloudBundle(raw)
}

// --- status -----------------------------------------------------------

func newCloudStatusCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:          "status",
		Short:        "Show this node's Cloud connection state",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store := nodeStoreForTest()
			st, err := store.LoadCloudState()
			if err != nil {
				return err
			}
			_, tokenErr := store.LoadCloudToken()
			tokenState := "configured"
			if tokenErr != nil {
				tokenState = "MISSING"
			}
			pullConfigured := st.PullURL != "" && st.TrustFingerprint != ""

			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"url":               st.URL,
					"enrolled_at":       st.EnrolledAt,
					"node_token":        tokenState,
					"pull_configured":   pullConfigured,
					"trust_fingerprint": st.TrustFingerprint,
					"last_sync_at":      st.LastSyncAt,
					"last_sync_result":  st.LastSyncResult,
				})
			}
			fmt.Fprintf(out, "cloud:             %s\n", st.URL)
			fmt.Fprintf(out, "enrolled:          %s\n", st.EnrolledAt)
			fmt.Fprintf(out, "node token:        %s\n", tokenState)
			fmt.Fprintf(out, "policy pull:       %v\n", pullConfigured)
			if st.TrustFingerprint != "" {
				fmt.Fprintf(out, "trust fingerprint: %s\n", st.TrustFingerprint)
			}
			if st.LastSyncAt != "" {
				fmt.Fprintf(out, "last sync:         %s (%s)\n", st.LastSyncAt, st.LastSyncResult)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}
