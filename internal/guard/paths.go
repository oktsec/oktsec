package guard

import "os"

// DefaultWatchPaths returns standard paths to monitor for AI tool config
// poisoning. Only paths that exist on disk are returned.
func DefaultWatchPaths() []string {
	candidates := []string{
		// AI tool configs
		"~/.claude/settings.json",
		"~/.claude/projects/",
		"~/.cursor/rules/",
		"~/.cursor/settings.json",
		"~/.continue/config.json",
		"~/.continue/config.yaml",
		"~/.windsurf/",
		"~/.copilot/",
		"~/.amp/",
		// Shell configs
		"~/.zshrc",
		"~/.bashrc",
		"~/.bash_profile",
		"~/.profile",
	}

	var exists []string
	for _, p := range candidates {
		expanded := expandHome(p)
		if _, err := os.Stat(expanded); err == nil {
			exists = append(exists, p)
		}
	}
	return exists
}
