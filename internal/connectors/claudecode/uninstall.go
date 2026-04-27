package claudecode

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// UninstallOptions mirrors InstallOptions for the symmetric removal
// path. The same symlink and dry-run guards apply; backups are
// always written so the operator can recover if uninstall removed
// more than they expected.
type UninstallOptions struct {
	HomeDir       string
	FollowSymlink bool
	DryRun        bool
	// IncludeLegacyV1 controls whether older oktsec hooks (no
	// --manifest v2 marker) are also removed. Default true:
	// uninstall is meant to clear all of oktsec's footprints,
	// not just the V2 ones.
	IncludeLegacyV1 bool
}

// UninstallResult reports what the symmetric removal did. Counts
// are split between v2 and legacy v1 so the doctor can show the
// operator exactly what footprint was cleared.
type UninstallResult struct {
	SettingsPath string `json:"settings_path"`
	BackupPath   string `json:"backup_path,omitempty"`
	Wrote        bool   `json:"wrote"`
	RemovedV2    int    `json:"removed_v2"`
	RemovedV1    int    `json:"removed_v1"`
	Skipped      string `json:"skipped,omitempty"`
}

// UninstallV2 removes every hook entry the installer owns from the
// user-scope Claude Code settings file. Uses the same atomic write
// + backup contract as InstallV2 so a botched uninstall never
// leaves the file in a torn state.
//
// Operator-added entries inside the same event family are
// preserved verbatim; only handlers that match
// isManifestV2Handler (and, when IncludeLegacyV1 is true, legacy
// oktsec entries) are dropped. Empty event arrays are removed
// entirely so the file does not gain "PreToolUse": [] cruft.
func UninstallV2(ctx context.Context, opts UninstallOptions) (UninstallResult, error) {
	if opts.HomeDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return UninstallResult{}, fmt.Errorf("resolving home dir: %w", err)
		}
		opts.HomeDir = h
	}

	settingsPath := filepath.Join(opts.HomeDir, ".claude", "settings.json")
	result := UninstallResult{SettingsPath: settingsPath}

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

	existing, mode, err := readRawSettings(writePath)
	if err != nil {
		return result, err
	}
	if len(existing) == 0 {
		result.Skipped = "settings file is empty or missing"
		return result, nil
	}

	removedV2, removedV1, mutated, err := stripManifest(existing, opts.IncludeLegacyV1)
	if err != nil {
		return result, err
	}
	result.RemovedV2 = removedV2
	result.RemovedV1 = removedV1

	if removedV2+removedV1 == 0 {
		result.Skipped = "no oktsec entries found"
		return result, nil
	}

	planned, err := encodeSettings(mutated)
	if err != nil {
		return result, err
	}
	current, _ := os.ReadFile(writePath)
	if bytesEqual(current, planned) {
		result.Skipped = "byte-identical to current file"
		return result, nil
	}
	if opts.DryRun {
		result.Skipped = "dry-run"
		return result, nil
	}

	backupPath, err := writeBackup(settingsPath, current, mode)
	if err != nil {
		return result, err
	}
	result.BackupPath = backupPath

	if err := atomicWrite(writePath, planned, mode); err != nil {
		return result, err
	}
	result.Wrote = true
	return result, nil
}

// stripManifest mirrors the install-side filter loop but removes
// every oktsec-owned handler instead of substituting a fresh one.
// Operator handlers retain their raw JSON payload so unknown
// fields (timeout, statusMessage, env, headers, future Claude
// additions) survive uninstall verbatim. Empty event arrays are
// dropped so uninstall is fully reversible — a follow-up install
// regenerates the keys cleanly.
func stripManifest(settings map[string]json.RawMessage, includeLegacyV1 bool) (int, int, map[string]json.RawMessage, error) {
	rawHooks, ok := settings["hooks"]
	if !ok || len(rawHooks) == 0 {
		return 0, 0, settings, nil
	}
	var perEvent map[string]json.RawMessage
	if err := json.Unmarshal(rawHooks, &perEvent); err != nil {
		return 0, 0, nil, fmt.Errorf("parsing hooks subtree: %w", err)
	}

	removedV2, removedV1 := 0, 0
	out := map[string][]preservedHookEntry{}
	for event, raw := range perEvent {
		entries, perr := decodePreservedEntries(raw)
		if perr != nil {
			return 0, 0, nil, fmt.Errorf("parsing hooks[%s]: %w", event, perr)
		}
		var keptEntries []preservedHookEntry
		for _, entry := range entries {
			var keptHandlers []json.RawMessage
			for _, h := range entry.Hooks {
				isV2, isLegacy := handlerOwnership(h)
				switch {
				case isV2:
					removedV2++
				case includeLegacyV1 && isLegacy:
					removedV1++
				default:
					keptHandlers = append(keptHandlers, h)
				}
			}
			if len(keptHandlers) > 0 {
				keptEntries = append(keptEntries, preservedHookEntry{
					Matcher: entry.Matcher,
					Hooks:   keptHandlers,
				})
			}
		}
		if len(keptEntries) > 0 {
			out[event] = keptEntries
		}
	}

	encoded := map[string]json.RawMessage{}
	for _, event := range sortedKeys(out) {
		body, err := json.Marshal(out[event])
		if err != nil {
			return 0, 0, nil, fmt.Errorf("encoding hooks[%s]: %w", event, err)
		}
		encoded[event] = body
	}
	if len(encoded) > 0 {
		body, err := json.Marshal(encoded)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("encoding hooks subtree: %w", err)
		}
		settings["hooks"] = body
	} else {
		delete(settings, "hooks")
	}
	return removedV2, removedV1, settings, nil
}
