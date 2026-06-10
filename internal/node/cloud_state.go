package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/safefile"
)

// Cloud connection state lives beside the node identity and goes
// through the SAME file discipline the identity uses: reads open with
// O_NOFOLLOW (safefile), writes are atomic tmp+rename and refuse
// pre-planted symlinks (writeFileSafe). cloud.json carries the policy
// trust fingerprint — the node's trust anchor — so a torn or redirected
// write of it is security-relevant state corruption.
//
//	cloud.json        — url, pull store URL, trust fingerprint, stamps
//	cloud-token       — the node's bearer token (secret, own file)
//	cloud-bundle.json — the last verified+applied bundle (for snapshots)

// CloudStateSchemaVersion freezes the cloud.json shape.
const CloudStateSchemaVersion = "oktsec_cloud_state.v1"

// maxCloudStateBytes bounds the state/token files on read.
const maxCloudStateBytes = 1 << 20

// CloudState is cloud.json. No secrets here: the node token has its
// own file so this state can be displayed by `cloud status`.
type CloudState struct {
	SchemaVersion    string `json:"schema_version"`
	URL              string `json:"url"`
	PullURL          string `json:"pull_url,omitempty"`
	TrustFingerprint string `json:"trust_fingerprint,omitempty"`
	EnrolledAt       string `json:"enrolled_at"`
	LastSyncAt       string `json:"last_sync_at,omitempty"`
	LastSyncResult   string `json:"last_sync_result,omitempty"`
}

func (s IdentityStore) cloudStatePath() string { return filepath.Join(s.Dir, "cloud.json") }
func (s IdentityStore) cloudTokenPath() string { return filepath.Join(s.Dir, "cloud-token") }

// CloudBundlePath is where `cloud sync` caches the last verified bundle
// so snapshots can echo the active policy.
func (s IdentityStore) CloudBundlePath() string { return filepath.Join(s.Dir, "cloud-bundle.json") }

// LoadCloudState reads cloud.json. A missing file is reported with the
// enroll remediation, distinct from a corrupt one.
func (s IdentityStore) LoadCloudState() (*CloudState, error) {
	p := s.cloudStatePath()
	raw, err := safefile.ReadFileMax(p, maxCloudStateBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("this node is not enrolled with a Cloud (run `oktsec cloud enroll --url <cloud> --token <enrollment-token>`)")
		}
		return nil, err
	}
	var st CloudState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if st.SchemaVersion != CloudStateSchemaVersion {
		return nil, fmt.Errorf("%s has schema %q, want %q", p, st.SchemaVersion, CloudStateSchemaVersion)
	}
	return &st, nil
}

// SaveCloudState writes cloud.json atomically (0600).
func (s IdentityStore) SaveCloudState(st *CloudState) error {
	st.SchemaVersion = CloudStateSchemaVersion
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSafe(s.cloudStatePath(), raw, 0o600)
}

// LoadCloudToken reads the node's Cloud bearer token.
func (s IdentityStore) LoadCloudToken() (string, error) {
	raw, err := safefile.ReadFileMax(s.cloudTokenPath(), maxCloudStateBytes)
	if err != nil {
		return "", fmt.Errorf("node token missing (re-run `oktsec cloud enroll`): %w", err)
	}
	token := string(bytes.TrimSpace(raw))
	if token == "" {
		return "", fmt.Errorf("node token file is empty (re-run `oktsec cloud enroll`)")
	}
	return token, nil
}

// SaveCloudToken writes the node's Cloud bearer token atomically (0600).
func (s IdentityStore) SaveCloudToken(token string) error {
	return writeFileSafe(s.cloudTokenPath(), []byte(token), 0o600)
}

// SaveCloudBundle caches the last verified bundle bytes atomically.
func (s IdentityStore) SaveCloudBundle(raw []byte) error {
	return writeFileSafe(s.CloudBundlePath(), raw, 0o600)
}
