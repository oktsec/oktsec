package claudecode

import (
	"encoding/json"
	"fmt"
	"strings"
)

// expectedEventFamilies is the Phase 2 hook manifest the spec calls for
// (section 2). Phase 1 only reports which of these are missing; it
// never installs them. Kept as a sorted slice so HookRef.Expected
// renders the same on every run.
var expectedEventFamilies = []string{
	"PreToolUse",         // pre-action / blocking
	"PostToolUse",        // observed / feedback
	"PostToolUseFailure", // observed / failure surface
	"PostToolBatch",      // observed / batched failures
	"SubagentStart",      // observed actor lifecycle
	"SubagentStop",
	"SessionStart", // observed session lifecycle
	"SessionEnd",
	"InstructionsLoaded", // observed config-change surface
	"CwdChanged",
	"FileChanged",
	"PermissionRequest", // pre-action / blocking
	"PermissionDenied",
	"Stop",
	"StopFailure",
	"TaskCreated",
	"TaskCompleted",
	"ConfigChange",
}

// blockingEventFamilies is the subset of hooks that can deny an
// action before Claude executes it. Used to populate
// HookRef.BlockingCap so the doctor can report "this hook is in a
// blocking event family" without callers having to know the list.
var blockingEventFamilies = map[string]bool{
	"PreToolUse":        true,
	"PermissionRequest": true,
}

// readHooks walks user + project + local settings files and emits one
// HookRef per (event, hook handler) pair. Returns the inventory's
// hooks list and any parse problems encountered. Read-only.
//
// Plugin / managed / agent-frontmatter hooks are deliberately
// out-of-scope for Phase 1: they require resolving plugin metadata
// from disk, and the spec marks that as a Phase 2 follow-up.
func readHooks(opts ReadOptions) ([]HookRef, []ConnectorProblem) {
	var hooks []HookRef
	var problems []ConnectorProblem

	scopes := []struct {
		scope string
		path  string
	}{
		{"user", opts.HomeDir + "/.claude/settings.json"},
		{"project", opts.ProjectDir + "/.claude/settings.json"},
		{"local", opts.ProjectDir + "/.claude/settings.local.json"},
	}
	for _, s := range scopes {
		// Skip empty project/local scopes when no project was supplied —
		// the path would be ".claude/settings.json" against cwd, which
		// is misleading. The doctor's UI shows the inspected paths so
		// the operator still sees what scope was checked.
		if s.scope != "user" && opts.ProjectDir == "" {
			continue
		}
		settings, prob := readSettings(s.path)
		if prob != nil {
			problems = append(problems, *prob)
		}
		if settings == nil {
			continue
		}
		// Surface disable / restrict knobs so the Phase 2 installer
		// can refuse to write hooks the operator (or a managed
		// policy) has globally neutered.
		problems = append(problems, disableKnobProblems(s.scope, s.path, settings)...)
		if settings.Hooks != nil {
			hooks = append(hooks, parseHookEntries(s.scope, s.path, settings.Hooks)...)
		}
	}
	return hooks, problems
}

// disableKnobProblems converts the three Claude Code "silently
// neuter every hook" flags into ConnectorProblem rows. The installer
// reads the codes, not the raw bools, so a future config-shape
// change only needs to update the parser in settings.go.
func disableKnobProblems(scope, path string, s *rawSettings) []ConnectorProblem {
	var ps []ConnectorProblem
	if s.DisableAllHooks != nil && *s.DisableAllHooks {
		ps = append(ps, ConnectorProblem{
			Code:     "CC-HOOKS-GLOBALLY-DISABLED",
			Severity: "risk",
			Title:    fmt.Sprintf("Claude Code hooks are globally disabled in %s settings", scope),
			Detail:   fmt.Sprintf("disableAllHooks: true at %s. Until this is removed, no oktsec hook will fire.", path),
			FixKind:  "manual",
		})
	}
	if s.AllowManagedHooksOnly != nil && *s.AllowManagedHooksOnly {
		ps = append(ps, ConnectorProblem{
			Code:     "CC-HOOKS-MANAGED-ONLY",
			Severity: "risk",
			Title:    fmt.Sprintf("Claude Code restricts hooks to managed scope in %s settings", scope),
			Detail:   fmt.Sprintf("allowManagedHooksOnly: true at %s. User and project hooks are blocked, including any oktsec install at non-managed scope.", path),
			FixKind:  "manual",
		})
	}
	if s.AllowedHTTPHookURLs != nil && len(*s.AllowedHTTPHookURLs) == 0 {
		ps = append(ps, ConnectorProblem{
			Code:     "CC-HOOKS-HTTP-URLS-RESTRICTED",
			Severity: "warning",
			Title:    fmt.Sprintf("HTTP hooks are blocked by an empty allowlist in %s settings", scope),
			Detail:   fmt.Sprintf("allowedHttpHookUrls is set to [] at %s. Command hooks (oktsec's default) still work, but any future HTTP variant would be silently dropped.", path),
			FixKind:  "manual",
		})
	}
	return ps
}

// HookInstallBlockedReasons returns the inventory problems that must
// be cleared before the Phase 2 installer can safely write a new
// manifest. Empty slice means "safe to install". Centralised so the
// doctor and the installer agree on the refusal contract.
func HookInstallBlockedReasons(inv Inventory) []ConnectorProblem {
	var blockers []ConnectorProblem
	for _, p := range inv.Problems {
		switch p.Code {
		case "CC-HOOKS-GLOBALLY-DISABLED", "CC-HOOKS-MANAGED-ONLY":
			blockers = append(blockers, p)
		}
	}
	return blockers
}

// parseHookEntries flattens the {event: [{matcher, hooks: [handler]}]}
// shape into a list of HookRef. Each handler becomes one row so the
// doctor table can print "PreToolUse | * | command | oktsec hook --port"
// without callers having to walk the nested array.
func parseHookEntries(scope, path string, perEvent map[string]json.RawMessage) []HookRef {
	var rows []HookRef
	for _, event := range sortedKeys(perEvent) {
		raw := perEvent[event]
		var entries []rawHookEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			// Some configs store one entry as an object, not array;
			// fall back to single-entry decode before giving up.
			var single rawHookEntry
			if err2 := json.Unmarshal(raw, &single); err2 != nil {
				continue
			}
			entries = []rawHookEntry{single}
		}
		for _, entry := range entries {
			for _, h := range entry.Hooks {
				rows = append(rows, HookRef{
					Scope:       scope,
					Path:        path,
					Event:       event,
					Matcher:     entry.Matcher,
					Type:        h.Type,
					Command:     h.Command,
					URL:         h.URL,
					IsOktsec:    isOktsecHookHandler(h),
					Expected:    isExpectedEvent(event),
					BlockingCap: blockingEventFamilies[event],
				})
			}
		}
	}
	return rows
}

// isOktsecHookHandler returns true when the handler clearly invokes
// the oktsec hook subcommand. Conservative on purpose: matching only
// "oktsec hook" as a token avoids flagging unrelated commands that
// happen to contain "oktsec" in a path comment.
func isOktsecHookHandler(h rawHookHandler) bool {
	if h.Type == "command" {
		// We accept either `oktsec hook` or a quoted path ending in
		// `oktsec` followed by `hook`, because run.go writes the
		// absolute binary path on first install.
		cmd := strings.ToLower(h.Command)
		if strings.Contains(cmd, "oktsec hook") {
			return true
		}
		// Cover quoted absolute path: "/usr/local/bin/oktsec" hook
		if strings.Contains(cmd, "/oktsec\" hook") || strings.Contains(cmd, "/oktsec hook") {
			return true
		}
	}
	if h.Type == "http" && strings.Contains(h.URL, "/hooks/event") {
		return true
	}
	return false
}

// ManifestV2Marker is the literal flag the Phase 2 installer adds to
// every command it writes. Inventory and uninstall both look for it
// to know which entries are theirs to manage. The flag is parsed
// (and ignored beyond its tagging role) by oktsec hook so Claude
// Code never sees a foreign key in the JSON.
const ManifestV2Marker = "--manifest v2"

// isManifestV2Handler returns true when the handler is an oktsec
// hook entry written by the Phase 2 installer. Used by the merge
// algorithm to decide which entries it owns and may safely
// rewrite/remove.
func isManifestV2Handler(h rawHookHandler) bool {
	if h.Type != "command" {
		return false
	}
	if !isOktsecHookHandler(h) {
		return false
	}
	return strings.Contains(h.Command, ManifestV2Marker)
}

// isLegacyOktsecHandler returns true for a v1 oktsec hook that
// predates the manifest marker. The installer upgrades these
// in-place without leaving duplicates.
func isLegacyOktsecHandler(h rawHookHandler) bool {
	return isOktsecHookHandler(h) && !isManifestV2Handler(h)
}

// isExpectedEvent reports whether the named event family is part of
// the Phase 2 hook manifest the spec calls for. Used to populate
// HookRef.Expected so the doctor can show "yes this event is part of
// the planned manifest" without re-reading the spec.
func isExpectedEvent(event string) bool {
	for _, e := range expectedEventFamilies {
		if e == event {
			return true
		}
	}
	return false
}

// MissingExpectedEvents returns the Phase 2 events that are NOT yet
// installed via an oktsec hook in any scope. Used by health.go and
// the doctor command to report the gap without having to enumerate
// the planned manifest at the call site.
func MissingExpectedEvents(hooks []HookRef) []string {
	covered := map[string]bool{}
	for _, h := range hooks {
		if h.IsOktsec {
			covered[h.Event] = true
		}
	}
	var missing []string
	for _, e := range expectedEventFamilies {
		if !covered[e] {
			missing = append(missing, e)
		}
	}
	return missing
}
