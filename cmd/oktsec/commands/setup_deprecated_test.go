package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSetupDeprecatedZeroDiscoveryPointsToRun pins the Phase 4F-0 copy
// contract for the deprecated `oktsec setup` command. The previous
// "Install an MCP server first, then run 'oktsec setup' again" line
// led users into a stale onboarding path that ignored Claude Code
// runtime client surfaces. This test fails if that copy ever reappears
// or if the new "Use `oktsec run`" line goes missing.
func TestSetupDeprecatedZeroDiscoveryPointsToRun(t *testing.T) {
	body := readSetupSource(t)

	for _, banned := range []string{
		// The dead-end copy: this implied installing an MCP server was a
		// prerequisite for Oktsec, even though `oktsec run` can register
		// Claude Code without one.
		"Install an MCP server first",
		"run 'oktsec setup' again",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("setup.go contains banned phrase %q", banned)
		}
	}

	for _, required := range []string{
		// Deprecation must point users to the current onboarding path.
		"Use `oktsec run`",
		"runtime client setup",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("setup.go missing required phrase %q", required)
		}
	}
}

// TestSetupCmd_LongAdvertisesDeprecation makes sure the help text users
// see when they run `oktsec setup --help` is honest about which command
// is the current onboarding path.
func TestSetupCmd_LongAdvertisesDeprecation(t *testing.T) {
	cmd := newSetupCmd()
	if !strings.Contains(strings.ToLower(cmd.Short), "deprecated") {
		t.Errorf("Short = %q, want it to contain 'deprecated'", cmd.Short)
	}
	if !strings.Contains(cmd.Long, "`oktsec run`") {
		t.Errorf("Long must point users at `oktsec run`; got %q", cmd.Long)
	}
}

// readSetupSource locates setup.go from the test's source path so the
// test does not depend on the working directory `go test` was launched
// from. setup.go lives next to this test file.
func readSetupSource(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate setup.go")
	}
	path := filepath.Join(filepath.Dir(thisFile), "setup.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read setup.go: %v", err)
	}
	return string(data)
}
