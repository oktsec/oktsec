package apply

// Order 9A.2 v2 commit. CommitV2 writes a verified v2 projection to the config
// using the SAME safety protocol as v1 Commit (patch original YAML -> validate
// via the real load path -> exclusive backup -> atomic rename -> dir fsync;
// refuses symlink / read-only / anchored-YAML). It does NOT reimplement the
// protocol: it reuses every helper from write.go (mapGet, mapSet, guardAnchored,
// anchorReferenced, isExplicitMapping, backupOriginal, writeExclusive,
// maxConfigBytes). The only v2-specific part is patch coverage: v2 can touch
// rules (global) plus, per agent, allowed_tools, egress, suspended,
// blocked_content, and scan_profile, across MULTIPLE agents (v1 scoped to one).
//
// CommitV2 does NOT write the anti-rollback state file; the command does that
// only after CommitV2 returns success, so a failed write never advances the
// sequence.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/safefile"
	"gopkg.in/yaml.v3"
)

// CommitV2 writes the v2 plan's projected changes to targetConfig. Call it only
// for a plan with changes and no unsupported items; it returns the backup path.
func CommitV2(plan *PlanV2, targetConfig string) (string, error) {
	if plan == nil || plan.projected == nil {
		return "", ErrNoProjection
	}

	info, err := os.Lstat(targetConfig)
	if err != nil {
		return "", fmt.Errorf("apply: stat config %q: %w", targetConfig, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("apply: config %q is a symlink (rejected for security)", targetConfig)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("apply: config %q is not a regular file", targetConfig)
	}
	mode := info.Mode().Perm()

	if probe, err := os.OpenFile(targetConfig, os.O_WRONLY, 0); err != nil {
		return "", fmt.Errorf("apply: config %q is not writable: %w", targetConfig, err)
	} else {
		_ = probe.Close()
	}

	orig, err := safefile.ReadFileMax(targetConfig, maxConfigBytes)
	if err != nil {
		return "", fmt.Errorf("apply: read original config: %w", err)
	}

	patched, err := patchConfigYAMLV2(orig, plan)
	if err != nil {
		return "", fmt.Errorf("apply: %w", err)
	}

	dir := filepath.Dir(targetConfig)
	tmp, err := os.CreateTemp(dir, filepath.Base(targetConfig)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("apply: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(patched); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", fmt.Errorf("apply: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", fmt.Errorf("apply: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", fmt.Errorf("apply: close temp: %w", err)
	}
	loaded, err := config.Load(tmpPath)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("apply: patched config does not load: %w", err)
	}
	if err := loaded.Validate(); err != nil {
		cleanup()
		return "", fmt.Errorf("apply: patched config is invalid: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		cleanup()
		return "", fmt.Errorf("apply: chmod temp: %w", err)
	}

	backupPath, err := backupOriginal(targetConfig, orig, mode)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("apply: create backup: %w", err)
	}

	if err := os.Rename(tmpPath, targetConfig); err != nil {
		cleanup()
		return backupPath, fmt.Errorf("apply: atomic replace %q (backup kept at %q): %w", targetConfig, backupPath, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return backupPath, nil
}

// patchConfigYAMLV2 applies only the v2 plan's governed changes onto the
// original YAML document, preserving every untouched field verbatim. It patches
// the global rules section and, per changed agent, that agent's governed fields.
func patchConfigYAMLV2(original []byte, plan *PlanV2) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return nil, fmt.Errorf("parse original config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("original config is not a YAML mapping")
	}
	root := doc.Content[0]

	// Determine which sections changed. Track, per agent, which governed fields
	// were touched so we patch only those keys.
	var patchRules bool
	agentFields := map[string]map[string]bool{} // agent -> field -> true
	touch := func(agent, field string) {
		m := agentFields[agent]
		if m == nil {
			m = map[string]bool{}
			agentFields[agent] = m
		}
		m[field] = true
	}
	for _, c := range plan.Changes {
		switch c.Kind {
		case "rule_override", "rule_reset_default":
			patchRules = true
		case "agent_allowed_tools":
			touch(c.Agent, "allowed_tools")
		case "agent_egress_allowed_domains", "agent_egress_denied_domains":
			touch(c.Agent, "egress")
		case "agent_suspended":
			touch(c.Agent, "suspended")
		case "agent_blocked_content":
			touch(c.Agent, "blocked_content")
		case "agent_scan_profile":
			touch(c.Agent, "scan_profile")
		}
	}

	if patchRules {
		if err := guardAnchored(&doc, mapGet(root, "rules"), "rules"); err != nil {
			return nil, err
		}
		var n yaml.Node
		if err := n.Encode(plan.projected.Rules); err != nil {
			return nil, fmt.Errorf("encode rules: %w", err)
		}
		mapSet(root, "rules", &n)
	}

	if len(agentFields) > 0 {
		agents := mapGet(root, "agents")
		if agents == nil || agents.Kind != yaml.MappingNode {
			// agents reachable only via alias/merge: materialize the whole resolved
			// map (governed changes + others) so real apply matches dry-run.
			var n yaml.Node
			if err := n.Encode(plan.projected.Agents); err != nil {
				return nil, fmt.Errorf("encode agents: %w", err)
			}
			mapSet(root, "agents", &n)
		} else {
			for agentName, fields := range agentFields {
				proj, ok := plan.projected.Agents[agentName]
				if !ok {
					return nil, fmt.Errorf("agent %q not in projected config", agentName)
				}
				node := mapGet(agents, agentName)
				if !isExplicitMapping(node) {
					// Agent reachable only via alias/merge: materialize the fully
					// resolved agent as an explicit key.
					var n yaml.Node
					if err := n.Encode(proj); err != nil {
						return nil, fmt.Errorf("encode agent %q: %w", agentName, err)
					}
					mapSet(agents, agentName, &n)
					continue
				}
				if node.Anchor != "" && anchorReferenced(&doc, node.Anchor) {
					return nil, fmt.Errorf("agent %q has a YAML anchor %q referenced elsewhere; inline it before applying policy", agentName, node.Anchor)
				}
				if err := patchAgentFieldV2(&doc, node, agentName, fields, proj); err != nil {
					return nil, err
				}
			}
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("marshal patched config: %w", err)
	}
	return out, nil
}

// patchAgentFieldV2 patches the changed governed keys of one explicit agent
// mapping in place, preserving its other fields and any merge. Each key is
// anchor-guarded before replacement.
func patchAgentFieldV2(doc *yaml.Node, node *yaml.Node, agentName string, fields map[string]bool, proj config.Agent) error {
	set := func(key string, val any) error {
		if err := guardAnchored(doc, mapGet(node, key), fmt.Sprintf("the agent's %s", key)); err != nil {
			return err
		}
		var n yaml.Node
		if err := n.Encode(val); err != nil {
			return fmt.Errorf("encode %s for agent %q: %w", key, agentName, err)
		}
		mapSet(node, key, &n)
		return nil
	}
	if fields["allowed_tools"] {
		if err := set("allowed_tools", proj.AllowedTools); err != nil {
			return err
		}
	}
	if fields["egress"] {
		if err := set("egress", proj.Egress); err != nil {
			return err
		}
	}
	if fields["suspended"] {
		if err := set("suspended", proj.Suspended); err != nil {
			return err
		}
	}
	if fields["blocked_content"] {
		if err := set("blocked_content", proj.BlockedContent); err != nil {
			return err
		}
	}
	if fields["scan_profile"] {
		if err := set("scan_profile", proj.ScanProfile); err != nil {
			return err
		}
	}
	return nil
}
