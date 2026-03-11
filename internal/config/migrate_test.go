package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMigrateConfig_NoMigrations(t *testing.T) {
	data := []byte("version: \"1\"\nserver:\n  port: 8080\n")
	out, applied, err := MigrateConfig(data)
	require.NoError(t, err)
	assert.False(t, applied)
	assert.Equal(t, data, out)
}

func TestMigrateConfig_InvalidYAML(t *testing.T) {
	data := []byte(":::invalid")
	out, applied, err := MigrateConfig(data)
	require.NoError(t, err)
	assert.False(t, applied)
	assert.Equal(t, data, out)
}

func TestMigrateConfig_WithMigration(t *testing.T) {
	// Temporarily add a test migration
	orig := migrations
	migrations = []migration{
		{
			description: "rename old_field to new_field",
			apply: func(root *yaml.Node) bool {
				idx := findKey(root, "old_field")
				if idx < 0 {
					return false
				}
				root.Content[idx].Value = "new_field"
				return true
			},
		},
	}
	t.Cleanup(func() { migrations = orig })

	data := []byte("old_field: hello\nversion: \"1\"\n")
	out, applied, err := MigrateConfig(data)
	require.NoError(t, err)
	assert.True(t, applied)
	assert.Contains(t, string(out), "new_field")
	assert.NotContains(t, string(out), "old_field")
}

func TestMigrateConfig_MoveToNested(t *testing.T) {
	orig := migrations
	migrations = []migration{
		{
			description: "move root keys_dir into identity.keys_dir",
			apply: func(root *yaml.Node) bool {
				idx := findKey(root, "keys_dir")
				if idx < 0 {
					return false
				}
				val := root.Content[idx+1]
				removeKeyAt(root, idx)
				identity := ensureMapping(root, "identity")
				if findKey(identity, "keys_dir") < 0 {
					keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "keys_dir"}
					identity.Content = append(identity.Content, keyNode, val)
				}
				return true
			},
		},
	}
	t.Cleanup(func() { migrations = orig })

	data := []byte("version: \"1\"\nkeys_dir: ./my-keys\n")
	out, applied, err := MigrateConfig(data)
	require.NoError(t, err)
	assert.True(t, applied)
	assert.Contains(t, string(out), "identity")
	assert.Contains(t, string(out), "keys_dir: ./my-keys")
	assert.NotContains(t, string(out), "\nkeys_dir:") // no root-level keys_dir
}

func TestFindKey(t *testing.T) {
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("a: 1\nb: 2\nc: 3"), &doc))
	root := doc.Content[0]
	assert.Equal(t, 0, findKey(root, "a"))
	assert.Equal(t, 2, findKey(root, "b"))
	assert.Equal(t, 4, findKey(root, "c"))
	assert.Equal(t, -1, findKey(root, "d"))
}
