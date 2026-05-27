package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/safefile"
	"gopkg.in/yaml.v3"
)

// maxConfigBytes caps the original config the backup/patch reads (mirrors config.Load).
const maxConfigBytes = 1 << 20 // 1 MiB

// ErrNoProjection is returned when Commit is given a plan with no computed
// target config (DryRun must run first and succeed).
var ErrNoProjection = errors.New("apply: plan has no projected config to commit")

// Commit writes the plan's projected changes to targetConfig using a backup +
// atomic-replace protocol. Call it only for a plan that has changes and no
// unsupported items; it returns the created backup path.
//
// Only the governed sections (rules; the target agent's allowed_tools and
// egress) are rewritten — they are patched onto the operator's original YAML
// document, so unrelated fields and any load-time defaults (e.g. db_path) are
// preserved verbatim rather than re-marshaled from the defaulted struct.
//
// Sequence (spec 7A.3 §4 / §5): patch the original -> write the patched bytes
// to an exclusive temp in the same dir -> validate THOSE bytes via the real
// load path (defaults + migrations) -> exclusive backup of the exact original
// bytes -> atomic rename of the validated temp over the config -> parent dir
// fsync. The config path is not mutated until the patched config has validated
// AND the backup exists; a failed rename leaves the original and backup intact.
func Commit(plan *Plan, targetConfig string) (string, error) {
	if plan == nil || plan.projected == nil {
		return "", ErrNoProjection
	}

	// Re-check the path right before writing: never follow a symlink, never
	// write through a directory or irregular file.
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

	// Refuse a read-only config: os.Rename would replace it via directory
	// permissions, so a plain mode/regular-file check is not enough. Probing
	// O_WRONLY respects the real permissions (owner/group/ACL) portably; it
	// neither truncates nor writes.
	if probe, err := os.OpenFile(targetConfig, os.O_WRONLY, 0); err != nil {
		return "", fmt.Errorf("apply: config %q is not writable: %w", targetConfig, err)
	} else {
		_ = probe.Close()
	}

	orig, err := safefile.ReadFileMax(targetConfig, maxConfigBytes)
	if err != nil {
		return "", fmt.Errorf("apply: read original config: %w", err)
	}

	patched, err := patchConfigYAML(orig, plan)
	if err != nil {
		return "", fmt.Errorf("apply: %w", err)
	}

	dir := filepath.Dir(targetConfig)

	// Write the patched bytes to an exclusive temp in the same directory and
	// validate THOSE bytes through the real load path before any backup or
	// config mutation. The validated temp is the file we rename — no rewrite.
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

	// 15: exclusive timestamped backup of the exact original bytes, created
	// only after validation passed. If this fails, the config is untouched.
	backupPath, err := backupOriginal(targetConfig, orig, mode)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("apply: create backup: %w", err)
	}

	// 18-19: atomic replace. On failure the original config and the backup
	// both remain; the temp is removed.
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

// patchConfigYAML applies only the plan's governed changes onto the original
// YAML document, preserving every untouched field (and any load-time default
// the operator never wrote — e.g. db_path) verbatim. Governed sections that
// actually changed are re-serialized from the validated projection.
func patchConfigYAML(original []byte, plan *Plan) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return nil, fmt.Errorf("parse original config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("original config is not a YAML mapping")
	}
	root := doc.Content[0]

	var patchRules, patchTools, patchEgress bool
	for _, c := range plan.Changes {
		switch c.Kind {
		case "rule_override", "rule_reset_default":
			patchRules = true
		case "agent_allowed_tools":
			patchTools = true
		case "agent_egress_allowed_domains", "agent_egress_denied_domains":
			patchEgress = true
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

	if patchTools || patchEgress {
		proj, ok := plan.projected.Agents[plan.Agent]
		if !ok {
			return nil, fmt.Errorf("agent %q not in projected config", plan.Agent)
		}
		agents := mapGet(root, "agents")
		switch {
		case agents == nil || agents.Kind != yaml.MappingNode:
			// The whole agents section is reachable only via a YAML alias
			// ("agents: *all") or a root-level `<<` merge — config.Load resolved
			// it, so dry-run saw the agent. Materialize the resolved agents map
			// (target's governed changes + the others) as an explicit mapping so
			// real apply matches dry-run instead of treating it as missing.
			var n yaml.Node
			if err := n.Encode(plan.projected.Agents); err != nil {
				return nil, fmt.Errorf("encode agents: %w", err)
			}
			mapSet(root, "agents", &n)

		case isExplicitMapping(mapGet(agents, plan.Agent)):
			// Explicit agent mapping (including one with a `<<` merge key):
			// patch only the governed keys in place, preserving the agent's
			// other fields and its merge.
			node := mapGet(agents, plan.Agent)
			// If the agent node itself is an anchor referenced by another agent,
			// patching its children would leak the change to that aliasing agent
			// (and dry-run only scoped the change to this agent). Refuse rather
			// than silently change a non-targeted agent.
			if node.Anchor != "" && anchorReferenced(&doc, node.Anchor) {
				return nil, fmt.Errorf("agent %q has a YAML anchor %q referenced elsewhere; inline it before applying policy", plan.Agent, node.Anchor)
			}
			if patchTools {
				if err := guardAnchored(&doc, mapGet(node, "allowed_tools"), "the agent's allowed_tools"); err != nil {
					return nil, err
				}
				var n yaml.Node
				if err := n.Encode(proj.AllowedTools); err != nil {
					return nil, fmt.Errorf("encode allowed_tools: %w", err)
				}
				mapSet(node, "allowed_tools", &n)
			}
			if patchEgress {
				if err := guardAnchored(&doc, mapGet(node, "egress"), "the agent's egress"); err != nil {
					return nil, err
				}
				var n yaml.Node
				if err := n.Encode(proj.Egress); err != nil {
					return nil, fmt.Errorf("encode egress: %w", err)
				}
				mapSet(node, "egress", &n)
			}

		default:
			// The agent is reachable only via a YAML alias value
			// ("voice-ai: *defaults") or an agents-level `<<` merge — config.Load
			// resolved it, so dry-run saw it. Materialize the fully-resolved
			// agent (inherited fields + governed changes) as an explicit key so
			// real apply matches dry-run and no inherited field is lost.
			var n yaml.Node
			if err := n.Encode(proj); err != nil {
				return nil, fmt.Errorf("encode agent %q: %w", plan.Agent, err)
			}
			mapSet(agents, plan.Agent, &n)
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("marshal patched config: %w", err)
	}
	return out, nil
}

// backupOriginal creates an exclusive backup of data beside targetConfig,
// preferring the spec name "<config>.bak.YYYYMMDDTHHMMSSZ". Seconds-resolution
// names collide for two applies in the same second (or a pre-existing backup),
// so on collision it appends ".N" until a unique name succeeds — a valid apply
// is never aborted by a backup-name clash.
func backupOriginal(targetConfig string, data []byte, mode os.FileMode) (string, error) {
	base := targetConfig + ".bak." + time.Now().UTC().Format("20060102T150405Z")
	candidate := base
	for i := 1; i <= 100; i++ {
		err := writeExclusive(candidate, data, mode)
		if err == nil {
			return candidate, nil
		}
		if !os.IsExist(err) {
			return "", err
		}
		candidate = fmt.Sprintf("%s.%d", base, i)
	}
	return "", fmt.Errorf("could not create a unique backup for %q", targetConfig)
}

// guardAnchored refuses to replace oldNode when it (or a descendant) defines a
// YAML anchor that an alias elsewhere in the document references: replacing it
// would orphan that alias and emit invalid YAML. Rather than silently break the
// document or expand the operator's anchors, apply refuses and asks the operator
// to inline. A config with no anchors (the common case) is unaffected.
func guardAnchored(doc, oldNode *yaml.Node, field string) error {
	if oldNode == nil {
		return nil
	}
	anchors := map[string]bool{}
	collectAnchors(oldNode, anchors)
	if len(anchors) == 0 {
		return nil
	}
	aliases := map[string]bool{}
	collectAliasNames(doc, aliases)
	for name := range anchors {
		if aliases[name] {
			return fmt.Errorf("%s defines a YAML anchor %q referenced elsewhere; inline it before applying policy", field, name)
		}
	}
	return nil
}

// collectAnchors records every anchor name defined in the subtree rooted at n.
func collectAnchors(n *yaml.Node, out map[string]bool) {
	if n == nil {
		return
	}
	if n.Anchor != "" {
		out[n.Anchor] = true
	}
	for _, c := range n.Content {
		collectAnchors(c, out)
	}
}

// collectAliasNames records every anchor name referenced by an alias in the doc.
func collectAliasNames(n *yaml.Node, out map[string]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.AliasNode && n.Value != "" {
		out[n.Value] = true
	}
	for _, c := range n.Content {
		collectAliasNames(c, out)
	}
}

// anchorReferenced reports whether an alias anywhere in doc references the
// given anchor name.
func anchorReferenced(doc *yaml.Node, name string) bool {
	if name == "" {
		return false
	}
	aliases := map[string]bool{}
	collectAliasNames(doc, aliases)
	return aliases[name]
}

// isExplicitMapping reports whether n is a concrete mapping node (not nil, an
// alias, or a scalar).
func isExplicitMapping(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.MappingNode
}

// mapGet returns the value node for key in a mapping node, or nil.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapSet sets key to val in a mapping node, replacing an existing value or
// appending a new key/value pair.
func mapSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}

// writeExclusive creates path with O_EXCL — it never overwrites an existing
// file and never follows a symlink at path — writes data, fsyncs, and closes.
// On any write/sync failure the partial file is removed.
func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
