package config

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// migration defines a single config field migration.
type migration struct {
	description string
	apply       func(root *yaml.Node) bool // returns true if migration was applied
}

// migrations is the ordered list of config migrations.
// Add new migrations at the end as the config schema evolves.
var migrations []migration

// MigrateConfig checks raw YAML data for known old field names
// and returns the migrated data plus whether any migration was applied.
// If no migrations are needed, returns the original data unchanged.
func MigrateConfig(data []byte) ([]byte, bool, error) {
	if len(migrations) == 0 {
		return data, false, nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return data, false, nil // parse error → skip migration, let Load handle it
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return data, false, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return data, false, nil
	}

	applied := false
	for _, m := range migrations {
		if m.apply(root) {
			applied = true
		}
	}

	if !applied {
		return data, false, nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return data, false, err
	}
	_ = enc.Close()
	return buf.Bytes(), true, nil
}

// findKey returns the index of a key in a mapping node, or -1.
func findKey(mapping *yaml.Node, key string) int {
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// removeKeyAt removes a key-value pair at the given index from a mapping node.
func removeKeyAt(mapping *yaml.Node, idx int) {
	mapping.Content = append(mapping.Content[:idx], mapping.Content[idx+2:]...)
}

// ensureMapping finds or creates a mapping child under the given key.
func ensureMapping(parent *yaml.Node, key string) *yaml.Node {
	idx := findKey(parent, key)
	if idx >= 0 {
		return parent.Content[idx+1]
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode
}
