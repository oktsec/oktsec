package node

import (
	"encoding/json"
	"testing"
)

// toJSON returns the JSON marshalling of v as a string. Test helper.
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// requireJSON marshals or fails the test.
func requireJSON(t *testing.T, v any) string {
	t.Helper()
	s, err := toJSON(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return s
}
