package claudecode

import (
	"encoding/json"
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
		if settings == nil || settings.Hooks == nil {
			continue
		}
		hooks = append(hooks, parseHookEntries(s.scope, s.path, settings.Hooks)...)
	}
	return hooks, problems
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
