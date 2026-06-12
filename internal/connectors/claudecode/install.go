package claudecode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PlannedHookEntry is one event family + handler the installer would
// write. Exposed so callers (the doctor command, future dashboard
// preview) can render the planned manifest before it touches disk.
type PlannedHookEntry struct {
	Event       string `json:"event"`
	Matcher     string `json:"matcher,omitempty"`
	Type        string `json:"type"`
	Command     string `json:"command"`
	TimeoutSecs int    `json:"timeout,omitempty"`
	Status      string `json:"statusMessage,omitempty"`
}

// InstallOptions controls where and how the Phase 2 manifest is
// written. Defaults match the conservative posture the spec calls
// for: user scope only, refuse symlinks, refuse when global disable
// knobs are present.
type InstallOptions struct {
	HomeDir       string // override $HOME for tests; "" => os.UserHomeDir
	BinaryPath    string // absolute path to the oktsec binary; "" => auto-detect
	GatewayPort   int    // gateway port the hook will POST to; required (>0)
	FollowSymlink bool   // when true, write through symlinks instead of refusing
	DryRun        bool   // when true, return the planned actions without writing
}

// InstallResult summarises what InstallV2 did (or would do, in dry-run).
// Designed for both the human doctor output and structured JSON.
type InstallResult struct {
	SettingsPath string             `json:"settings_path"`
	BackupPath   string             `json:"backup_path,omitempty"`
	Plan         []PlannedHookEntry `json:"plan"`
	Wrote        bool               `json:"wrote"`
	UpgradedV1   int                `json:"upgraded_v1"`
	Skipped      string             `json:"skipped,omitempty"` // reason when wrote=false
}

// installerVersion is the schema tag baked into every entry's
// command line via ManifestV2Marker. Bumping this constant is the
// signal that future installers should treat older entries as
// upgrade candidates.
const installerVersion = "v2"

// InstallV2 writes the Phase 2 hook manifest into the user-scope
// Claude Code settings file. Read-by-default, write-only-when-needed:
//
//   - Refuses when an inventory blocker exists (disableAllHooks /
//     allowManagedHooksOnly). Operators must clear those first.
//   - Refuses when the settings file is a symlink, unless
//     opts.FollowSymlink is set.
//   - Backs up the existing file to <path>.oktsec-pre-<UTCstamp>.bak
//     with the original mode bits before any rewrite.
//   - Writes through a sibling tempfile + fsync + rename for
//     POSIX-atomic replacement.
//   - Skips the rewrite entirely when the planned content is
//     byte-identical to the current file (idempotency exit).
//
// InstallV2 never touches keys other than `hooks`. Operator entries
// inside the same event family are preserved; only entries the
// installer owns (carrying ManifestV2Marker, or legacy v1 oktsec
// hooks pending upgrade) are removed before the new entry is
// appended.
func InstallV2(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if opts.GatewayPort <= 0 {
		return InstallResult{}, fmt.Errorf("gateway port required (got %d)", opts.GatewayPort)
	}
	if opts.HomeDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return InstallResult{}, fmt.Errorf("resolving home dir: %w", err)
		}
		opts.HomeDir = h
	}
	if opts.BinaryPath == "" {
		exe, err := os.Executable()
		if err != nil || exe == "" {
			return InstallResult{}, fmt.Errorf("resolving oktsec binary path: %w", err)
		}
		opts.BinaryPath = exe
	}

	settingsPath := filepath.Join(opts.HomeDir, ".claude", "settings.json")
	result := InstallResult{
		SettingsPath: settingsPath,
		Plan:         buildPlan(opts.BinaryPath, opts.GatewayPort),
	}

	// Pre-flight via inventory. Only the disable-knob blockers stop
	// the install; missing-hooks problems are exactly what we are
	// here to fix.
	inv := Read(ctx, ReadOptions{
		HomeDir:          opts.HomeDir,
		SkipVersionProbe: true,
	})
	if blockers := HookInstallBlockedReasons(inv); len(blockers) > 0 {
		return result, &InstallBlockedError{Reasons: blockers}
	}

	// Symlink handling: refuse by default so dotfiles repos are not
	// silently rewritten. With --follow-symlink, resolve to the real
	// target so the atomic rename writes through the link instead of
	// replacing the link with a regular file.
	writePath := settingsPath
	if info, lerr := os.Lstat(settingsPath); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
		if !opts.FollowSymlink {
			return result, &SymlinkRefusedError{Path: settingsPath}
		}
		resolved, err := filepath.EvalSymlinks(settingsPath)
		if err != nil {
			return result, fmt.Errorf("resolving symlink %s: %w", settingsPath, err)
		}
		writePath = resolved
	}

	// Read existing settings as raw JSON so unknown keys round-trip
	// untouched. Decoding into a typed struct would silently drop
	// any operator-added top-level field on rewrite.
	existing, mode, err := readRawSettings(writePath)
	if err != nil {
		return result, err
	}

	// Ensure the directory containing the write target exists. When
	// we resolved a symlink the target's parent might not be ~/.claude,
	// so we use writePath, not settingsPath.
	if err := os.MkdirAll(filepath.Dir(writePath), 0o700); err != nil {
		return result, fmt.Errorf("creating settings directory: %w", err)
	}

	// Apply the manifest to the parsed settings tree.
	upgraded, mutated, err := applyManifest(existing, result.Plan)
	if err != nil {
		return result, err
	}
	result.UpgradedV1 = upgraded

	// Encode the mutated tree. Stable indentation = stable diffs.
	planned, err := encodeSettings(mutated)
	if err != nil {
		return result, err
	}

	// Idempotency exit: if the current file equals the planned
	// content (after our canonical encoding), skip the rewrite.
	current, _ := os.ReadFile(writePath)
	if bytesEqual(current, planned) {
		result.Skipped = "byte-identical to current file"
		return result, nil
	}

	if opts.DryRun {
		result.Skipped = "dry-run"
		return result, nil
	}

	// Backup before any write. The backup carries the original mode
	// so a restore preserves the file's permission posture. We
	// always back up next to the symlink (settingsPath) so the
	// operator can find it from the canonical path even when the
	// real file lives in a dotfiles repo.
	backupPath, err := writeBackup(settingsPath, current, mode)
	if err != nil {
		return result, err
	}
	result.BackupPath = backupPath

	// Atomic write to the resolved write path so a symlink at
	// settingsPath keeps pointing at the same on-disk file.
	if err := atomicWrite(writePath, planned, mode); err != nil {
		return result, err
	}
	result.Wrote = true
	return result, nil
}

// InstallBlockedError signals that an inventory problem must be
// cleared before the installer will proceed. The doctor formats the
// reasons; tests assert on errors.As.
type InstallBlockedError struct {
	Reasons []ConnectorProblem
}

func (e *InstallBlockedError) Error() string {
	codes := make([]string, len(e.Reasons))
	for i, p := range e.Reasons {
		codes[i] = p.Code
	}
	return fmt.Sprintf("hook install refused: %s", strings.Join(codes, ", "))
}

// SymlinkRefusedError signals the settings file is a symlink and the
// caller did not opt in to following it. Surfaces in the doctor as a
// clear "pass --follow-symlink to override" message.
type SymlinkRefusedError struct {
	Path string
}

func (e *SymlinkRefusedError) Error() string {
	return fmt.Sprintf("refusing to follow symlink %s; pass --follow-symlink to override", e.Path)
}

// readRawSettings reads the settings file into a generic map so
// unknown keys round-trip untouched. Returns (empty map, default
// mode, nil) when the file does not exist — that is a valid
// "first-time install" path.
func readRawSettings(path string) (map[string]json.RawMessage, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]json.RawMessage{}, 0o600, nil
		}
		return nil, 0, fmt.Errorf("reading %s: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if len(data) > 0 {
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, 0, fmt.Errorf("parsing %s: %w (refusing to overwrite a malformed file)", path, err)
		}
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return raw, mode, nil
}

// phase2EventSpec is one (event, matcher) pair the installer
// writes. Centralised so the install plan, the inventory's
// "missing events" report, and the runtime block-capability map
// all derive from one table. Adding an event family is a
// one-line change here.
type phase2EventSpec struct {
	event   string
	matcher string
}

// phase2EventSpecs is the canonical Phase 2 hook manifest. The
// inventory derives expectedEventFamilies from this list so the
// "missing events" report always matches what the installer
// writes; previously the two lists drifted (FileChanged was
// expected but never installed, Notification was installed but
// not expected) and the doctor never reached `ready` after a
// successful install.
//
// FileChanged is intentionally absent: the docs require literal
// filename matchers and the spec defers it to Phase 3. Adding it
// here without a watch-list would create silent matcher drift.
var phase2EventSpecs = []phase2EventSpec{
	// Pre-action / blocking
	{"PreToolUse", "*"},
	{"PermissionRequest", "*"},

	// Post-action / observed
	{"PostToolUse", "*"},
	{"PostToolUseFailure", "*"},
	{"PostToolBatch", ""},
	{"Stop", ""},
	{"StopFailure", ""},
	{"PermissionDenied", ""},

	// Subagent + task lifecycle
	{"SubagentStart", "*"},
	{"SubagentStop", "*"},
	{"TaskCreated", ""},
	{"TaskCompleted", ""},

	// Session + config
	{"SessionStart", ""},
	{"SessionEnd", ""},
	{"InstructionsLoaded", ""},
	{"CwdChanged", ""},
	{"ConfigChange", ""},
	{"Notification", ""},
}

// Phase2EventNames returns the event-family names the installer
// writes, in stable order. Used by the inventory to compute the
// "missing events" gap report so the inventory and installer never
// drift again. Exported so external tooling (the dashboard's
// future Setup Health card) can render the same list.
func Phase2EventNames() []string {
	names := make([]string, len(phase2EventSpecs))
	for i, s := range phase2EventSpecs {
		names[i] = s.event
	}
	return names
}

// buildPlan composes the per-event entries the installer will
// write. Pure projection of phase2EventSpecs through the binary
// path + port, so a contract change to the command line is one
// edit.
func buildPlan(binary string, port int) []PlannedHookEntry {
	cmdFor := func(event string) string {
		return fmt.Sprintf("%q hook --port %d --event %s --manifest %s",
			binary, port, event, installerVersion)
	}
	statusFor := func(event string) string {
		return fmt.Sprintf("oktsec checking %s", event)
	}
	plan := make([]PlannedHookEntry, 0, len(phase2EventSpecs))
	for _, s := range phase2EventSpecs {
		plan = append(plan, PlannedHookEntry{
			Event:       s.event,
			Matcher:     s.matcher,
			Type:        "command",
			Command:     cmdFor(s.event),
			TimeoutSecs: 30,
			Status:      statusFor(s.event),
		})
	}
	return plan
}

// applyManifest rewrites the "hooks" subtree of the parsed settings
// map: filters out our own entries (v2 + legacy v1) per event,
// preserves operator entries verbatim (handler payloads stay as
// raw JSON so unknown fields like timeout / statusMessage / env
// survive the round-trip), and appends one fresh v2 entry per
// planned event. Returns the count of v1 entries upgraded, the
// mutated settings map, and any encode/decode error.
func applyManifest(settings map[string]json.RawMessage, plan []PlannedHookEntry) (int, map[string]json.RawMessage, error) {
	// Decode the current hooks subtree using the preservation
	// shape so handlers round-trip as raw JSON. The lossy rawHookEntry
	// type would silently drop any handler field we do not model
	// (timeout, statusMessage, env, headers, allowedEnvVars, future
	// Claude additions) on rewrite.
	current := map[string][]preservedHookEntry{}
	if rawHooks, ok := settings["hooks"]; ok && len(rawHooks) > 0 {
		var perEvent map[string]json.RawMessage
		if err := json.Unmarshal(rawHooks, &perEvent); err != nil {
			return 0, nil, fmt.Errorf("parsing hooks subtree: %w", err)
		}
		for event, raw := range perEvent {
			entries, perr := decodePreservedEntries(raw)
			if perr != nil {
				return 0, nil, fmt.Errorf("parsing hooks[%s]: %w", event, perr)
			}
			current[event] = entries
		}
	}

	plannedByEvent := map[string]PlannedHookEntry{}
	for _, p := range plan {
		plannedByEvent[p.Event] = p
	}

	upgradedV1 := 0
	out := map[string][]preservedHookEntry{}

	// 1) Pass through events not in our plan untouched. The raw
	// JSON handler payloads stay verbatim.
	for event, entries := range current {
		if _, planned := plannedByEvent[event]; planned {
			continue
		}
		out[event] = entries
	}

	// 2) For each planned event, filter operator handlers through
	// the ownership predicate, count v1 upgrades, then append the
	// fresh v2 entry. Operator handlers retain their raw JSON
	// payload so unknown fields are preserved.
	for _, p := range plan {
		var preserved []preservedHookEntry
		for _, entry := range current[p.Event] {
			kept := []json.RawMessage{}
			for _, raw := range entry.Hooks {
				isV2, isLegacy := handlerOwnership(raw)
				switch {
				case isV2:
					// Drop our previous v2 entry — about to write fresh.
				case isLegacy:
					upgradedV1++
				default:
					kept = append(kept, raw)
				}
			}
			if len(kept) > 0 {
				preserved = append(preserved, preservedHookEntry{
					Matcher: entry.Matcher,
					Hooks:   kept,
				})
			}
		}
		ownHandler, err := encodeOwnHandler(p)
		if err != nil {
			return 0, nil, err
		}
		preserved = append(preserved, preservedHookEntry{
			Matcher: p.Matcher,
			Hooks:   []json.RawMessage{ownHandler},
		})
		out[p.Event] = preserved
	}

	encoded := map[string]json.RawMessage{}
	for _, event := range sortedKeys(out) {
		entries := out[event]
		if len(entries) == 0 {
			continue
		}
		body, err := json.Marshal(entries)
		if err != nil {
			return 0, nil, fmt.Errorf("encoding hooks[%s]: %w", event, err)
		}
		encoded[event] = body
	}
	if len(encoded) > 0 {
		body, err := json.Marshal(encoded)
		if err != nil {
			return 0, nil, fmt.Errorf("encoding hooks subtree: %w", err)
		}
		settings["hooks"] = body
	} else {
		delete(settings, "hooks")
	}
	return upgradedV1, settings, nil
}

// decodePreservedEntries parses one event's raw JSON value into the
// preservation shape. Tolerates the older single-object form some
// configs use; either way the returned entries carry handler
// payloads as raw JSON for verbatim round-trip.
func decodePreservedEntries(raw json.RawMessage) ([]preservedHookEntry, error) {
	var entries []preservedHookEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		var single preservedHookEntry
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil, err
		}
		entries = []preservedHookEntry{single}
	}
	return entries, nil
}

// encodeOwnHandler produces the raw JSON shape for one oktsec hook
// handler. The output must match every field PlannedHookEntry
// advertises (timeout, statusMessage) so that --install-hooks
// --dry-run --json describes the same manifest the installer
// actually writes to disk. Earlier the timeout / status fields
// were dropped here while buildPlan kept them, leaving the dry-run
// preview lying about the on-disk state.
func encodeOwnHandler(p PlannedHookEntry) (json.RawMessage, error) {
	handler := map[string]any{
		"type":    p.Type,
		"command": p.Command,
	}
	if p.TimeoutSecs > 0 {
		handler["timeout"] = p.TimeoutSecs
	}
	if p.Status != "" {
		handler["statusMessage"] = p.Status
	}
	body, err := json.Marshal(handler)
	if err != nil {
		return nil, fmt.Errorf("encoding own handler for %s: %w", p.Event, err)
	}
	return body, nil
}

// encodeSettings serialises the raw settings map into the canonical
// on-disk form: 2-space indent, sorted top-level keys, trailing
// newline. Stable encoding is what makes the byte-equal idempotency
// check possible.
func encodeSettings(settings map[string]json.RawMessage) ([]byte, error) {
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build an ordered key sequence by marshalling as a
	// json.RawMessage stream. encoding/json does not preserve key
	// order from a map, so we assemble by hand.
	var buf strings.Builder
	buf.WriteString("{\n")
	for i, k := range keys {
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		valueBytes, err := indentValue(settings[k], "  ")
		if err != nil {
			return nil, fmt.Errorf("encoding key %q: %w", k, err)
		}
		buf.WriteString("  ")
		buf.Write(keyBytes)
		buf.WriteString(": ")
		buf.Write(valueBytes)
		if i < len(keys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")
	return []byte(buf.String()), nil
}

// indentValue re-marshals a single JSON value with a leading-line
// prefix of `prefix` so the assembled object reads consistently.
func indentValue(raw json.RawMessage, prefix string) ([]byte, error) {
	// Round-trip through Indent so map values reformat consistently
	// regardless of how the operator wrote them.
	var any interface{}
	if err := json.Unmarshal(raw, &any); err != nil {
		// Could not decode — return the raw value verbatim so we do
		// not lose data. This only happens on values we round-trip
		// from disk that were already valid JSON.
		return raw, nil
	}
	pretty, err := json.MarshalIndent(any, prefix, "  ")
	if err != nil {
		return nil, err
	}
	return pretty, nil
}

// writeBackup copies the current settings file to a sibling named
// settings.json.oktsec-pre-<UTCstamp>.bak, preserving the source
// file's mode bits. Returns the backup path.
//
// The timestamp includes nanoseconds because back-to-back operations
// (e.g. install followed by uninstall in the same test) can land
// inside the same UTC second; second-resolution collisions would
// abort the second backup with "already exists".
func writeBackup(path string, content []byte, mode os.FileMode) (string, error) {
	if len(content) == 0 {
		// First-time install: nothing to back up.
		return "", nil
	}
	stamp := strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000000000Z"), ".", "")
	backup := fmt.Sprintf("%s.oktsec-pre-%s.bak", path, stamp)
	if _, err := os.Stat(backup); err == nil {
		return "", fmt.Errorf("backup %s already exists; refusing to overwrite", backup)
	}
	if err := os.WriteFile(backup, content, mode); err != nil {
		return "", fmt.Errorf("writing backup %s: %w", backup, err)
	}
	return backup, nil
}

// atomicWrite writes data to path via a tempfile + fsync + rename
// + parent dir fsync. Mode is preserved through the rename.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".oktsec-settings-tmp-*")
	if err != nil {
		return fmt.Errorf("creating tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing tempfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing tempfile: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod tempfile: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename tempfile to %s: %w", path, err)
	}
	// Parent fsync ensures the rename is durable across crashes.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
