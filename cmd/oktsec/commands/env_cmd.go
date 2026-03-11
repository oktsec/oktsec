package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

func newEnvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Show oktsec environment variables in export format",
		Example: `  oktsec env
  oktsec env | grep OKTSEC_API_KEY`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnv()
		},
	}
}

type envVar struct {
	name     string
	value    string
	source   string
	required bool
}

func runEnv() error {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	// Best-effort config load
	cfg, _ := config.Load(cfgFile)
	if cfg == nil {
		cfg = config.Defaults()
	}

	// Best-effort .env load
	envPath := config.DefaultEnvPath()
	dotenv, _ := config.LoadEnv(envPath)

	var vars []envVar

	// --- Required ---
	apiKey, apiKeySource := resolveEnvVar("OKTSEC_API_KEY", dotenv, cfg.Server.APIKey)
	vars = append(vars, envVar{"OKTSEC_API_KEY", apiKey, apiKeySource, true})

	// --- Optional ---
	configVal, configSource := resolveEnvVar("OKTSEC_CONFIG", nil, cfgFile)
	vars = append(vars, envVar{"OKTSEC_CONFIG", configVal, configSource, false})

	vars = append(vars, envVar{"OKTSEC_HOME", config.HomeDir(), "default", false})

	portStr := fmt.Sprintf("%d", cfg.Server.Port)
	vars = append(vars, envVar{"OKTSEC_PORT", portStr, "config", false})

	bindVal := cfg.Server.Bind
	if bindVal == "" {
		bindVal = "127.0.0.1"
	}
	vars = append(vars, envVar{"OKTSEC_BIND", bindVal, sourceOrDefault(cfg.Server.Bind), false})

	vars = append(vars, envVar{"OKTSEC_LOG_LEVEL", cfg.Server.LogLevel, "config", false})

	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = config.DefaultDBPath()
	}
	vars = append(vars, envVar{"OKTSEC_DB_PATH", dbPath, sourceOrDefault(cfg.DBPath), false})

	keysDir := cfg.Identity.KeysDir
	if keysDir == "" {
		keysDir = config.DefaultKeysDir()
	}
	vars = append(vars, envVar{"OKTSEC_KEYS_DIR", keysDir, sourceOrDefault(cfg.Identity.KeysDir), false})

	// Print
	fmt.Println()
	fmt.Println("  oktsec env")
	fmt.Println("  ────────────────────────────────────────")
	fmt.Println()

	fmt.Println("  # Required")
	for _, v := range vars {
		if !v.required {
			continue
		}
		printEnvVar(v, green, red, dim)
	}

	fmt.Println()
	fmt.Println("  # Optional")
	for _, v := range vars {
		if v.required {
			continue
		}
		printEnvVar(v, green, red, dim)
	}
	fmt.Println()

	return nil
}

func printEnvVar(v envVar, green, red, dim func(a ...interface{}) string) {
	if v.value == "" {
		fmt.Printf("  %s  %s\n", red(fmt.Sprintf("export %s=", v.name)), dim("# not set"))
		return
	}
	// Mask secrets
	display := v.value
	if v.name == "OKTSEC_API_KEY" && len(display) > 8 {
		display = display[:4] + "..." + display[len(display)-4:]
	}
	fmt.Printf("  %s  %s\n",
		green(fmt.Sprintf("export %s=\"%s\"", v.name, display)),
		dim(fmt.Sprintf("# %s", v.source)))
}

func resolveEnvVar(name string, dotenv map[string]string, configVal string) (string, string) {
	if v := os.Getenv(name); v != "" {
		return v, "env"
	}
	if dotenv != nil {
		if v, ok := dotenv[name]; ok && v != "" {
			return v, filepath.Base(config.DefaultEnvPath())
		}
	}
	if configVal != "" {
		return configVal, "config"
	}
	return "", "not set"
}

func sourceOrDefault(val string) string {
	if val != "" {
		return "config"
	}
	return "default"
}
