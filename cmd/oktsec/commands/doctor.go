package commands

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

type checkResult struct {
	name   string
	status string // "pass", "warn", "fail"
	detail string
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run diagnostic checks on your oktsec setup",
		Example: `  oktsec doctor
  oktsec doctor --config /path/to/config.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor()
		},
	}
}

func runDoctor() error {
	fmt.Println()
	fmt.Println("  oktsec doctor")
	fmt.Println("  ────────────────────────────────────────")

	var results []checkResult

	// 1. Home directory
	results = append(results, checkHomeDir())

	// 2. Config
	cfg, cfgResult := checkConfig()
	results = append(results, cfgResult)

	// 3. Secrets file
	results = append(results, checkSecrets())

	if cfg != nil {
		// 4. DB accessible
		results = append(results, checkDB(cfg))

		// 5. Keypairs
		results = append(results, checkKeypairs(cfg))

		// 6. Port available
		results = append(results, checkPort(cfg))

		// 7. Rules compile
		results = append(results, checkRules(cfg))
	}

	// Print results
	var passed, warned, failed int
	for _, r := range results {
		icon := "✓"
		switch r.status {
		case "warn":
			icon = "!"
			warned++
		case "fail":
			icon = "✗"
			failed++
		default:
			passed++
		}
		fmt.Printf("  [%s]  %s: %s\n", icon, r.name, r.detail)
	}

	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  %d passed", passed)
	if warned > 0 {
		fmt.Printf(", %d warnings", warned)
	}
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	fmt.Println()
	fmt.Println()

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

func checkHomeDir() checkResult {
	home := config.HomeDir()
	info, err := os.Stat(home)
	if err != nil {
		return checkResult{"Home directory", "fail", fmt.Sprintf("%s does not exist", home)}
	}
	if !info.IsDir() {
		return checkResult{"Home directory", "fail", fmt.Sprintf("%s is not a directory", home)}
	}
	return checkResult{"Home directory", "pass", home}
}

func checkConfig() (*config.Config, checkResult) {
	path := cfgFile
	cfg, err := config.Load(path)
	if err != nil {
		return nil, checkResult{"Config", "fail", fmt.Sprintf("cannot load %s: %v", path, err)}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, checkResult{"Config", "warn", fmt.Sprintf("loaded but invalid: %v", err)}
	}
	return cfg, checkResult{"Config", "pass", path}
}

func checkSecrets() checkResult {
	envPath := config.DefaultEnvPath()
	info, err := os.Stat(envPath)
	if os.IsNotExist(err) {
		return checkResult{"Secrets", "warn", fmt.Sprintf("%s not found (run 'oktsec run' to generate)", envPath)}
	}
	if err != nil {
		return checkResult{"Secrets", "fail", fmt.Sprintf("cannot stat %s: %v", envPath, err)}
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return checkResult{"Secrets", "warn", fmt.Sprintf("%s has permissions %o (should be 600)", envPath, mode)}
	}
	return checkResult{"Secrets", "pass", fmt.Sprintf("%s (0%o)", envPath, mode)}
}

func checkDB(cfg *config.Config) checkResult {
	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = config.DefaultDBPath()
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return checkResult{"Audit DB", "fail", fmt.Sprintf("cannot open %s: %v", dbPath, err)}
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		return checkResult{"Audit DB", "fail", fmt.Sprintf("cannot access %s: %v", dbPath, err)}
	}
	return checkResult{"Audit DB", "pass", dbPath}
}

func checkKeypairs(cfg *config.Config) checkResult {
	keysDir := cfg.Identity.KeysDir
	if keysDir == "" {
		keysDir = config.DefaultKeysDir()
	}
	if len(cfg.Agents) == 0 {
		return checkResult{"Keypairs", "pass", "no agents configured"}
	}
	var missing []string
	for name := range cfg.Agents {
		keyFile := filepath.Join(keysDir, name+".key")
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return checkResult{"Keypairs", "warn", fmt.Sprintf("%d missing: %v", len(missing), missing)}
	}
	return checkResult{"Keypairs", "pass", fmt.Sprintf("%d agent(s) in %s", len(cfg.Agents), keysDir)}
}

func checkPort(cfg *config.Config) checkResult {
	bind := cfg.Server.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", bind, cfg.Server.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return checkResult{"Port", "warn", fmt.Sprintf("%s in use or unavailable", addr)}
	}
	_ = ln.Close()
	return checkResult{"Port", "pass", fmt.Sprintf("%s available", addr)}
}

func checkRules(cfg *config.Config) checkResult {
	scanner := engine.NewScanner(cfg.CustomRulesDir)
	defer scanner.Close()
	count := scanner.RulesCount(context.Background())
	if count == 0 {
		return checkResult{"Rules", "warn", "no rules loaded"}
	}
	return checkResult{"Rules", "pass", fmt.Sprintf("%d rules compiled", count)}
}
