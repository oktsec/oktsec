package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOpenClawConfig(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanOpenClawConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {
			"assistant": {"sandbox": true},
			"coder": {"sandbox": false}
		},
		"tools": {"profile": "standard", "allow": ["read", "write"]},
		"channels": {"slack": {"token": "xoxb-test"}},
		"dmPolicy": "restricted"
	}`)

	result, err := scanOpenClawConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if result.Client != "openclaw" {
		t.Errorf("client = %q, want openclaw", result.Client)
	}

	// Expect: 1 gateway + 2 agents + 1 channel = 4 servers
	if len(result.Servers) != 4 {
		t.Errorf("got %d servers, want 4", len(result.Servers))
	}

	found := map[string]bool{}
	for _, s := range result.Servers {
		found[s.Name] = true
	}
	if !found["openclaw-gateway"] {
		t.Error("missing openclaw-gateway entry")
	}
	if !found["channel-slack"] {
		t.Error("missing channel-slack entry")
	}
}

func TestScanOpenClawConfig_JSON5Comments(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		// This is a line comment
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		/* Block comment */
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "minimal"},
		"channels": {}
	}`)

	result, err := scanOpenClawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Client != "openclaw" {
		t.Errorf("client = %q, want openclaw", result.Client)
	}
	// 1 gateway + 1 agent = 2
	if len(result.Servers) != 2 {
		t.Errorf("got %d servers, want 2", len(result.Servers))
	}
}

func TestScanOpenClawConfig_NoAgents(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789},
		"tools": {"profile": "standard"},
		"channels": {}
	}`)

	result, err := scanOpenClawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only gateway entry when no agents or channels
	if len(result.Servers) != 1 {
		t.Errorf("got %d servers, want 1 (gateway only)", len(result.Servers))
	}
}

func TestScanOpenClawConfig_MissingFile(t *testing.T) {
	_, err := scanOpenClawConfig("/nonexistent/openclaw.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestScanOpenClawConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, "not json at all")

	_, err := scanOpenClawConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestStripJSON5Comments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "line comment",
			input: `{"key": "value" // comment` + "\n}",
			want:  `{"key": "value" ` + "\n}",
		},
		{
			name:  "block comment",
			input: `{"key": /* removed */ "value"}`,
			want:  `{"key":  "value"}`,
		},
		{
			name:  "comment-like inside string",
			input: `{"url": "http://example.com"}`,
			want:  `{"url": "http://example.com"}`,
		},
		{
			name:  "escaped quote in string",
			input: `{"msg": "say \"hello\" // not a comment"}`,
			want:  `{"msg": "say \"hello\" // not a comment"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripJSON5Comments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAssessOpenClawRisk_FullProfile(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "full"},
		"channels": {}
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "critical" {
		t.Errorf("level = %q, want critical", risk.Level)
	}
	if len(risk.Reasons) == 0 {
		t.Error("expected at least one reason")
	}
}

func TestAssessOpenClawRisk_ExecWithoutSandbox(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {"bot": {"sandbox": false}},
		"tools": {"profile": "standard", "allow": ["read", "exec"]},
		"channels": {}
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "critical" {
		t.Errorf("level = %q, want critical", risk.Level)
	}
}

func TestAssessOpenClawRisk_ExposedGateway(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "0.0.0.0"},
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "standard"},
		"channels": {}
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "high" {
		t.Errorf("level = %q, want high", risk.Level)
	}
}

func TestAssessOpenClawRisk_OpenDM(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "standard"},
		"channels": {},
		"dmPolicy": "open"
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "high" {
		t.Errorf("level = %q, want high", risk.Level)
	}
}

func TestAssessOpenClawRisk_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789},
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "standard"},
		"channels": {},
		"$include": ["../../../etc/secrets.json"]
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "critical" {
		t.Errorf("level = %q, want critical", risk.Level)
	}
	found := false
	for _, r := range risk.Reasons {
		if strings.Contains(r, "path traversal") {
			found = true
		}
	}
	if !found {
		t.Error("expected path traversal reason")
	}
}

func TestAssessOpenClawRisk_MessagingChannels(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "standard"},
		"channels": {"slack": {}, "telegram": {}}
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "medium" {
		t.Errorf("level = %q, want medium", risk.Level)
	}
}

func TestAssessOpenClawRisk_NoSandbox(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {"a": {"sandbox": false}, "b": {"sandbox": false}},
		"tools": {"profile": "standard"},
		"channels": {}
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "high" {
		t.Errorf("level = %q, want high", risk.Level)
	}
}

func TestAssessOpenClawRisk_Safe(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "standard", "allow": ["read"]},
		"channels": {},
		"dmPolicy": "restricted"
	}`)

	risk, err := AssessOpenClawRisk(path)
	if err != nil {
		t.Fatal(err)
	}
	if risk.Level != "low" {
		t.Errorf("level = %q, want low", risk.Level)
	}
	if len(risk.Reasons) != 0 {
		t.Errorf("expected no reasons, got %v", risk.Reasons)
	}
}

func TestAssessOpenClawRisk_MissingFile(t *testing.T) {
	_, err := AssessOpenClawRisk("/nonexistent/openclaw.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
