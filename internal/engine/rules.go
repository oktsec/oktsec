package engine

import (
	"io/fs"
	"path/filepath"

	"github.com/oktsec/oktsec/rules"
)

// ExtractRulesDir extracts embedded IAP rules to a temp directory
// and returns the path. Caller should clean up with os.RemoveAll.
func ExtractRulesDir() (string, error) {
	return extractEmbeddedRules()
}

// IAPRuleCount returns the number of embedded IAP rules files.
func IAPRuleCount() int {
	count := 0
	embedded := rules.FS()
	_ = fs.WalkDir(embedded, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".yaml" {
			count++
		}
		return nil
	})
	return count
}
