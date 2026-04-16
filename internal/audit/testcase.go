package audit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"gopkg.in/yaml.v3"
)

// Testcase represents a detection rule test case generated from production traffic.
type Testcase struct {
	RuleID    string `yaml:"rule_id"`
	Type      string `yaml:"type"`      // true_positive or false_positive
	Source    string `yaml:"source"`    // production
	Timestamp string `yaml:"timestamp"` // RFC3339
	Agent     string `yaml:"agent"`
	Tool      string `yaml:"tool"`
	Content   string `yaml:"content"`
	Severity  string `yaml:"severity"`
	Verdict   string `yaml:"verdict"` // block or quarantine
}

// TestcaseDir returns ~/.oktsec/testcases/, creating the directory if needed.
func TestcaseDir() (string, error) {
	dir := filepath.Join(config.HomeDir(), "testcases")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating testcases dir: %w", err)
	}
	return dir, nil
}

// ExportTestcase writes a testcase YAML file for a blocked/quarantined event.
// Content is redacted for credentials before writing.
func ExportTestcase(tc Testcase) (string, error) {
	dir, err := TestcaseDir()
	if err != nil {
		return "", err
	}

	// Redact credentials in content
	tc.Content = engine.RedactContent(tc.Content)

	// Generate filename: verdict-ruleID-timestamp.yaml
	ts := time.Now().UTC().Format("20060102-150405")
	safeRule := strings.ReplaceAll(strings.ToLower(tc.RuleID), "/", "-")
	filename := fmt.Sprintf("%s-%s-%s.yaml", tc.Verdict, safeRule, ts)
	path := filepath.Join(dir, filename)

	// Handle collision
	if _, err := os.Stat(path); err == nil {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.Content)))[:8]
		filename = fmt.Sprintf("%s-%s-%s-%s.yaml", tc.Verdict, safeRule, ts, hash)
		path = filepath.Join(dir, filename)
	}

	data, err := yaml.Marshal(tc)
	if err != nil {
		return "", fmt.Errorf("marshaling testcase: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("writing testcase: %w", err)
	}

	return path, nil
}

// LoadTestcases reads all YAML testcase files from the given directory.
func LoadTestcases(dir string) ([]Testcase, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cases []Testcase
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var tc Testcase
		if err := yaml.Unmarshal(data, &tc); err != nil {
			continue
		}
		cases = append(cases, tc)
	}
	return cases, nil
}
