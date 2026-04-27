package commands

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/oktsec/oktsec/internal/connectors/claudecode"
)

// TestDoctorClaudeCodeJSONShape locks in the JSON envelope external
// tooling (the Phase 5 AI Fix Assistant, future repair flows) will
// rely on. We exercise the helper directly instead of running the
// cobra subcommand so the test does not depend on the user's HOME or
// on the CLI being on PATH.
func TestDoctorClaudeCodeJSONShape(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(home+"/.claude", 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	inv := claudecode.Read(context.Background(), claudecode.ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})
	health := claudecode.DeriveHealth(inv, claudecode.HealthOptions{})

	out, err := json.Marshal(struct {
		Inventory claudecode.Inventory       `json:"inventory"`
		Health    claudecode.ConnectorHealth `json:"health"`
	}{Inventory: inv, Health: health})
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip into a permissive map so the test fails on missing
	// top-level keys rather than on field types we may extend later.
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v; payload=%s", err, out)
	}
	if _, ok := got["inventory"]; !ok {
		t.Errorf("missing 'inventory' key in output: %s", out)
	}
	if _, ok := got["health"]; !ok {
		t.Errorf("missing 'health' key in output: %s", out)
	}
}

// TestDoctorClaudeCodeIsRegistered makes sure newDoctorCmd attaches
// the claude-code subcommand and that it advertises the read-only
// docs string. A future contributor that drops the AddCommand call
// breaks the dashboard's expected workflow; this test catches it.
func TestDoctorClaudeCodeIsRegistered(t *testing.T) {
	root := newDoctorCmd()
	sub, _, err := root.Find([]string{"claude-code"})
	if err != nil || sub == nil || sub.Name() != "claude-code" {
		t.Fatalf("doctor claude-code subcommand not registered: %v", err)
	}
	if sub.Long == "" {
		t.Error("subcommand should carry a Long description")
	}
}
