package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The repository README is the public product reference operators,
// integrators, and reviewers consult before they touch anything else.
// It must agree with the dashboard surface (page count, page names,
// rule count) and with the security positioning (no universal
// visibility claims, hooks scoped to clients that emit them, LLM
// analysis described as optional/async/human-reviewed).
//
// Banned phrases here either previously appeared in the README or
// are recognized regression risks from past copy edits. Required
// phrases are the language the dashboard UX and desktop polish
// slices standardized on.
//
// Rule count: README mentions "268" intentionally as a current-
// release figure. The companion run.go / serve.go / dashboard
// templates render counts from the live scanner. If this test
// fails after a rule catalog change, update the literal AND verify
// the engine count with `oktsec rules` first.
func TestREADMEContract_Wording(t *testing.T) {
	body := readREADME(t)
	lower := strings.ToLower(body)

	for _, banned := range []string{
		// Universal-visibility / marketing-hero language the slice
		// removed. Reintroducing any of these would re-open the
		// "Oktsec sees everything" failure mode.
		"see everything your ai agents execute",
		"full visibility",
		"hooks intercept everything",
		"every tool call is a production action",
		"chain-of-thought",
		"chain of thought",
		"see exactly what the agent was thinking",
		"what the agent was thinking",
		// "auto-generates new detection rules" was the LLM page
		// overclaim. Generated rules carry pending_review by
		// default — README must describe them as suggestions.
		"auto-generates new detection rules",
		// 12-page count was stale after the dashboard reorg.
		// Drill-down routes (rule detail, session detail, custom
		// rules, category detail, coverage activity drawers) are
		// not primary navigation.
		"12 pages",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("README contains banned phrase %q", banned)
		}
	}

	// Required phrases are matched case-insensitively because the
	// README capitalizes some at the start of a sentence. The
	// contract is the wording, not the casing.
	for _, required := range []string{
		"routed through oktsec",
		"configured http hooks",
		"pre-action",
		"post-action",
		"human-reviewed",
		"no llm on the hot path",
		"11 primary pages",
	} {
		if !strings.Contains(lower, required) {
			t.Errorf("README missing required phrase %q (case-insensitive)", required)
		}
	}
}

// Stale rule-count literals (217, 230, 255) must not appear in the
// README. The current value is 268 and the spec is explicit: do not
// introduce other rule counts. A copy/paste regression that drops
// in an old number from a CHANGELOG or screenshot caption fires
// this test before it lands.
func TestREADMEContract_NoStaleRuleCounts(t *testing.T) {
	body := readREADME(t)
	for _, stale := range []string{"217 rules", "217 detection", "230 rules", "230 detection", "255 rules", "255 detection"} {
		if strings.Contains(body, stale) {
			t.Errorf("README contains stale rule-count literal %q; current release is 268 (verify with `oktsec rules`)", stale)
		}
	}
}

// readREADME locates the repository README from the test's source
// file path so the test does not depend on the working directory
// `go test` was launched from. The README lives three levels above
// this file: cmd/oktsec/commands/<this file>.
func readREADME(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate README")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	path := filepath.Join(repoRoot, "README.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read README at %s: %v", path, err)
	}
	return string(data)
}
