package claudecode

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFixtureHome assembles a fake $HOME with optional initial
// settings.json content, returning the home dir path so tests can
// pass it as InstallOptions.HomeDir. Centralized to avoid scattering
// MkdirAll boilerplate across cases.
func installFixtureHome(t *testing.T, settings string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if settings != "" {
		path := filepath.Join(home, ".claude", "settings.json")
		if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func readSettingsFile(t *testing.T, home string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal post-install settings: %v\nbody=%s", err, data)
	}
	return out
}

// TestInstallV2_FreshHomeWritesManifest exercises the happy path:
// no settings file exists, install creates one with every Phase 2
// event, no backup is needed (nothing to back up), and the manifest
// marker is present in the command string.
func TestInstallV2_FreshHomeWritesManifest(t *testing.T) {
	home := installFixtureHome(t, "")

	res, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Wrote {
		t.Errorf("expected Wrote=true, got skipped=%q", res.Skipped)
	}
	if res.BackupPath != "" {
		t.Errorf("first-time install should not back up: %q", res.BackupPath)
	}

	settings := readSettingsFile(t, home)
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks key missing or wrong type: %#v", settings["hooks"])
	}
	for _, must := range []string{"PreToolUse", "PostToolUse", "SubagentStart", "SessionStart"} {
		if _, ok := hooks[must]; !ok {
			t.Errorf("expected event %q in installed hooks", must)
		}
	}
	// Marker must be present in at least one command.
	if !strings.Contains(string(mustMarshal(t, settings)), ManifestV2Marker) {
		t.Error("ManifestV2Marker not found in any installed command")
	}
}

// TestInstallV2_RefusesWhenDisableAllHooks proves the disable-knob
// gate fires before any disk write. The settings file must be
// untouched after the refusal.
func TestInstallV2_RefusesWhenDisableAllHooks(t *testing.T) {
	home := installFixtureHome(t, `{"disableAllHooks": true}`)
	before, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))

	_, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	})
	var blocked *InstallBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected InstallBlockedError, got %v", err)
	}
	codes := make([]string, len(blocked.Reasons))
	for i, r := range blocked.Reasons {
		codes[i] = r.Code
	}
	if want := "CC-HOOKS-GLOBALLY-DISABLED"; !contains(codes, want) {
		t.Errorf("blocked reasons = %v, want to contain %q", codes, want)
	}

	after, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if string(before) != string(after) {
		t.Error("settings file mutated despite refusal")
	}
}

// TestInstallV2_RefusesSymlink default-refuses to follow a symlinked
// settings.json so dotfiles repos are not silently rewritten.
func TestInstallV2_RefusesSymlink(t *testing.T) {
	home := installFixtureHome(t, "")
	target := t.TempDir()
	realPath := filepath.Join(target, "settings-real.json")
	if err := os.WriteFile(realPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".claude", "settings.json")
	_ = os.Remove(link) // installFixtureHome did not create one
	if err := os.Symlink(realPath, link); err != nil {
		t.Fatal(err)
	}

	_, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	})
	var sym *SymlinkRefusedError
	if !errors.As(err, &sym) {
		t.Fatalf("expected SymlinkRefusedError, got %v", err)
	}

	// FollowSymlink=true should succeed and write through the symlink.
	res, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:       home,
		BinaryPath:    "/usr/local/bin/oktsec",
		GatewayPort:   9090,
		FollowSymlink: true,
	})
	if err != nil {
		t.Fatalf("FollowSymlink install: %v", err)
	}
	if !res.Wrote {
		t.Errorf("FollowSymlink install should have written; skipped=%q", res.Skipped)
	}
	// The real target file should now contain hooks; the symlink in
	// home should still resolve to it.
	body, _ := os.ReadFile(realPath)
	if !strings.Contains(string(body), "PreToolUse") {
		t.Error("symlinked target was not updated by FollowSymlink install")
	}
}

// TestInstallV2_PreservesOperatorEntries asserts the merge-no-replace
// contract: an operator's existing SessionStart hook survives an
// oktsec install.
func TestInstallV2_PreservesOperatorEntries(t *testing.T) {
	existing := `{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "echo hello" }
        ]
      }
    ]
  }
}
`
	home := installFixtureHome(t, existing)
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if !strings.Contains(string(body), "echo hello") {
		t.Errorf("operator SessionStart hook lost on install; body=%s", body)
	}
	if !strings.Contains(string(body), ManifestV2Marker) {
		t.Errorf("oktsec entry not added; body=%s", body)
	}
}

// TestInstallV2_UpgradesLegacyV1 confirms an existing v1 oktsec hook
// is replaced (not duplicated) by the v2 manifest.
func TestInstallV2_UpgradesLegacyV1(t *testing.T) {
	v1 := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          { "type": "command", "command": "/usr/local/bin/oktsec hook --port 9090" }
        ]
      }
    ]
  }
}
`
	home := installFixtureHome(t, v1)
	res, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.UpgradedV1 == 0 {
		t.Error("expected UpgradedV1 > 0")
	}

	settings := readSettingsFile(t, home)
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("PreToolUse should have exactly one entry after upgrade, got %d", len(pre))
	}
	cmd := mustExtractCommand(t, pre[0])
	if !strings.Contains(cmd, ManifestV2Marker) {
		t.Errorf("upgraded entry missing marker; cmd=%s", cmd)
	}
	if strings.Contains(cmd, "oktsec hook --port 9090\"") {
		t.Errorf("legacy v1 command still present alongside v2: cmd=%s", cmd)
	}
}

// TestInstallV2_IsIdempotent guarantees a second install produces a
// byte-identical file (and skips the rewrite).
func TestInstallV2_IsIdempotent(t *testing.T) {
	home := installFixtureHome(t, "")
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatal(err)
	}
	body1, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))

	res2, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Wrote {
		t.Error("second install should be idempotent (skipped)")
	}
	if res2.Skipped == "" {
		t.Error("expected Skipped reason on idempotent re-run")
	}
	body2, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if string(body1) != string(body2) {
		t.Error("settings file changed across idempotent runs")
	}
}

// TestInstallV2_BackupCarriesOriginalMode proves the backup file
// preserves the source file's permission bits so a manual restore
// keeps the operator's posture.
func TestInstallV2_BackupCarriesOriginalMode(t *testing.T) {
	home := installFixtureHome(t, `{"hooks":{}}`)
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.Chmod(settingsPath, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.BackupPath == "" {
		t.Fatal("expected backup path")
	}
	info, err := os.Stat(res.BackupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("backup mode = %o, want 644", info.Mode().Perm())
	}
}

// TestUninstallV2_RemovesOnlyOurEntries confirms operator entries
// survive uninstall and oktsec footprints are gone.
func TestUninstallV2_RemovesOnlyOurEntries(t *testing.T) {
	existing := `{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "echo hello" }
        ]
      }
    ]
  }
}
`
	home := installFixtureHome(t, existing)
	// Install first so there is something to remove.
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatal(err)
	}
	res, err := UninstallV2(context.Background(), UninstallOptions{
		HomeDir:         home,
		IncludeLegacyV1: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.RemovedV2 == 0 {
		t.Error("expected RemovedV2 > 0")
	}

	body, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if !strings.Contains(string(body), "echo hello") {
		t.Errorf("operator hook removed by uninstall; body=%s", body)
	}
	if strings.Contains(string(body), ManifestV2Marker) {
		t.Errorf("oktsec marker survived uninstall; body=%s", body)
	}
}

// TestInstallV2_OnDiskHandlerCarriesPlannedFields locks in the
// promise that --install-hooks --dry-run --json advertises the
// same manifest the installer actually writes. Previously the
// dry-run plan listed timeout + statusMessage, but encodeOwnHandler
// dropped them on the way to disk; an operator inspecting the
// installed file saw a sparser entry than the dry-run claimed.
//
// The test installs against a fixture home, then reads
// settings.json off disk and walks every oktsec entry asserting
// the planned fields are present.
func TestInstallV2_OnDiskHandlerCarriesPlannedFields(t *testing.T) {
	home := installFixtureHome(t, "")
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatal(err)
	}
	planned := buildPlan("/usr/local/bin/oktsec", 9090)
	plannedByEvent := map[string]PlannedHookEntry{}
	for _, p := range planned {
		plannedByEvent[p.Event] = p
	}

	settings := readSettingsFile(t, home)
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks key missing or wrong type: %#v", settings["hooks"])
	}
	for event, want := range plannedByEvent {
		entries, ok := hooks[event].([]any)
		if !ok {
			t.Errorf("event %s missing from installed hooks", event)
			continue
		}
		// Walk every entry and find the oktsec one. Operator
		// entries are ignored — this test pins our own handler.
		var ownHandler map[string]any
		for _, raw := range entries {
			entry, _ := raw.(map[string]any)
			handlers, _ := entry["hooks"].([]any)
			for _, h := range handlers {
				cmd, _ := h.(map[string]any)["command"].(string)
				if strings.Contains(cmd, ManifestV2Marker) {
					ownHandler = h.(map[string]any)
					break
				}
			}
			if ownHandler != nil {
				break
			}
		}
		if ownHandler == nil {
			t.Errorf("no oktsec handler installed for event %s", event)
			continue
		}
		if got, _ := ownHandler["timeout"].(float64); int(got) != want.TimeoutSecs {
			t.Errorf("event %s: installed timeout = %v, want %d", event, ownHandler["timeout"], want.TimeoutSecs)
		}
		if got, _ := ownHandler["statusMessage"].(string); got != want.Status {
			t.Errorf("event %s: installed statusMessage = %q, want %q", event, got, want.Status)
		}
	}
}

// TestPhase2EventNames_MatchesInstalledPlan locks in the P1
// invariant: the inventory's "missing events" report and the
// installer's plan derive from the same source. A drift here
// would mean the doctor never reaches `ready` after a clean
// install (or, in the other direction, would mark events
// "missing" that we silently never install).
func TestPhase2EventNames_MatchesInstalledPlan(t *testing.T) {
	plan := buildPlan("/usr/local/bin/oktsec", 9090)
	planEvents := map[string]bool{}
	for _, p := range plan {
		planEvents[p.Event] = true
	}
	for _, name := range Phase2EventNames() {
		if !planEvents[name] {
			t.Errorf("Phase2EventNames lists %q but buildPlan does not install it", name)
		}
	}
	for event := range planEvents {
		var found bool
		for _, name := range Phase2EventNames() {
			if name == event {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("buildPlan installs %q but Phase2EventNames does not list it (missing-events report would be wrong)", event)
		}
	}
}

// TestMissingExpectedEvents_EmptyAfterInstall is the operator-
// visible guarantee that the doctor's "missing manifest events"
// list is empty once the installer has run.
func TestMissingExpectedEvents_EmptyAfterInstall(t *testing.T) {
	home := installFixtureHome(t, "")
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatal(err)
	}
	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})
	if missing := MissingExpectedEvents(inv.Hooks); len(missing) > 0 {
		t.Errorf("MissingExpectedEvents non-empty after fresh install: %v", missing)
	}
}

// TestInstallV2_PreservesUnknownHandlerFields locks in the P2
// merge contract: an operator hook with `timeout` and
// `statusMessage` fields (or any other Claude-supported field
// the inventory does not model) must round-trip verbatim across
// install. The previous typed-struct decode silently dropped them.
func TestInstallV2_PreservesUnknownHandlerFields(t *testing.T) {
	existing := `{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash(git *)",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/operator/audit.sh",
            "timeout": 600,
            "statusMessage": "operator audit running",
            "if": "Bash(git push *)",
            "allowedEnvVars": ["GIT_AUTHOR"],
            "shell": "bash"
          }
        ]
      }
    ]
  }
}
`
	home := installFixtureHome(t, existing)
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	for _, expected := range []string{
		`"timeout"`,
		`"statusMessage"`,
		`"if"`,
		`"allowedEnvVars"`,
		`"shell"`,
		`"operator audit running"`,
		`"GIT_AUTHOR"`,
		`"Bash(git push *)"`,
		`"/opt/operator/audit.sh"`,
	} {
		if !strings.Contains(string(body), expected) {
			t.Errorf("operator field %s lost on install round-trip; body=%s", expected, body)
		}
	}
	// And the oktsec entry must still be present.
	if !strings.Contains(string(body), ManifestV2Marker) {
		t.Errorf("oktsec entry missing after preserve-fields install; body=%s", body)
	}
}

// TestUninstallV2_PreservesUnknownHandlerFields confirms the
// symmetric guarantee on the uninstall path.
func TestUninstallV2_PreservesUnknownHandlerFields(t *testing.T) {
	existing := `{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash(git *)",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/operator/audit.sh",
            "timeout": 600,
            "statusMessage": "operator audit running"
          }
        ]
      }
    ]
  }
}
`
	home := installFixtureHome(t, existing)
	if _, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := UninstallV2(context.Background(), UninstallOptions{
		HomeDir:         home,
		IncludeLegacyV1: true,
	}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	for _, expected := range []string{
		`"timeout"`,
		`"statusMessage"`,
		`"operator audit running"`,
		`"/opt/operator/audit.sh"`,
	} {
		if !strings.Contains(string(body), expected) {
			t.Errorf("operator field %s lost on uninstall round-trip; body=%s", expected, body)
		}
	}
}

// TestInstallV2_DryRunMakesNoMutation locks in the dry-run contract.
func TestInstallV2_DryRunMakesNoMutation(t *testing.T) {
	home := installFixtureHome(t, "")
	res, err := InstallV2(context.Background(), InstallOptions{
		HomeDir:     home,
		BinaryPath:  "/usr/local/bin/oktsec",
		GatewayPort: 9090,
		DryRun:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Wrote {
		t.Error("dry-run install should not write")
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err == nil {
		t.Error("dry-run install created settings file")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustExtractCommand(t *testing.T, entry any) string {
	t.Helper()
	m, ok := entry.(map[string]any)
	if !ok {
		t.Fatalf("entry is not a map: %#v", entry)
	}
	hooks, ok := m["hooks"].([]any)
	if !ok || len(hooks) == 0 {
		t.Fatalf("entry has no hooks slice: %#v", entry)
	}
	h := hooks[0].(map[string]any)
	cmd, _ := h["command"].(string)
	return cmd
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
