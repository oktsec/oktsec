package commands

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

type checkResult struct {
	name       string
	status     string // "pass", "warn", "fail"
	detail     string
	repair     func() error // nil = not repairable
	repairHint string
}

func newDoctorCmd() *cobra.Command {
	var repair bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run diagnostic checks on your oktsec setup",
		Example: `  oktsec doctor
  oktsec doctor --repair`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(repair)
		},
	}
	cmd.Flags().BoolVar(&repair, "repair", false, "attempt to fix issues automatically")
	return cmd
}

func runDoctor(repair bool) error {
	bold := color.New(color.Bold).SprintFunc()

	fmt.Println()
	fmt.Printf("  %s\n", bold("oktsec doctor"))
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

	// Print results and attempt repairs
	var passed, warned, failed, repaired int
	for i, r := range results {
		printCheck(r)

		if repair && r.status != "pass" && r.repair != nil {
			dim := color.New(color.Faint).SprintFunc()
			fmt.Printf("       %s %s...\n", dim("repairing:"), r.repairHint)

			if err := r.repair(); err != nil {
				fmt.Printf("       %s %v\n", color.RedString("repair failed:"), err)
			} else {
				fmt.Printf("       %s\n", color.GreenString("repaired"))
				results[i].status = "pass"
				repaired++
			}
		}

		switch results[i].status {
		case "warn":
			warned++
		case "fail":
			failed++
		default:
			passed++
		}
	}

	fmt.Println("  ────────────────────────────────────────")
	summary := fmt.Sprintf("  %s", color.GreenString("%d passed", passed))
	if repaired > 0 {
		summary += fmt.Sprintf(", %s", color.CyanString("%d repaired", repaired))
	}
	if warned > 0 {
		summary += fmt.Sprintf(", %s", color.YellowString("%d warnings", warned))
	}
	if failed > 0 {
		summary += fmt.Sprintf(", %s", color.RedString("%d failed", failed))
	}
	fmt.Println(summary)
	fmt.Println()

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

func printCheck(r checkResult) {
	switch r.status {
	case "pass":
		fmt.Printf("  %s  %s: %s\n", color.GreenString("✓"), r.name, r.detail)
	case "warn":
		fmt.Printf("  %s  %s: %s\n", color.YellowString("!"), r.name, r.detail)
	case "fail":
		fmt.Printf("  %s  %s: %s\n", color.RedString("✗"), r.name, r.detail)
	}
}

func checkHomeDir() checkResult {
	home := config.HomeDir()
	info, err := os.Stat(home)
	if err != nil {
		return checkResult{
			name: "Home directory", status: "fail",
			detail:     fmt.Sprintf("%s does not exist", home),
			repair:     func() error { return os.MkdirAll(home, 0o700) },
			repairHint: "create " + home,
		}
	}
	if !info.IsDir() {
		return checkResult{name: "Home directory", status: "fail", detail: fmt.Sprintf("%s is not a directory", home)}
	}
	return checkResult{name: "Home directory", status: "pass", detail: home}
}

func checkConfig() (*config.Config, checkResult) {
	path := cfgFile
	cfg, err := config.Load(path)
	if err != nil {
		return nil, checkResult{name: "Config", status: "fail", detail: fmt.Sprintf("cannot load %s: %v", path, err)}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, checkResult{name: "Config", status: "warn", detail: fmt.Sprintf("loaded but invalid: %v", err)}
	}
	return cfg, checkResult{name: "Config", status: "pass", detail: path}
}

func checkSecrets() checkResult {
	envPath := config.DefaultEnvPath()
	info, err := os.Stat(envPath)
	if os.IsNotExist(err) {
		return checkResult{
			name: "Secrets", status: "warn",
			detail:     fmt.Sprintf("%s not found (run 'oktsec run' to generate)", envPath),
			repair:     func() error { return config.EnsureEnvFile(envPath) },
			repairHint: "create .env with random API key",
		}
	}
	if err != nil {
		return checkResult{name: "Secrets", status: "fail", detail: fmt.Sprintf("cannot stat %s: %v", envPath, err)}
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return checkResult{
			name: "Secrets", status: "warn",
			detail:     fmt.Sprintf("%s has permissions %o (should be 600)", envPath, mode),
			repair:     func() error { return os.Chmod(envPath, 0o600) },
			repairHint: "chmod 600",
		}
	}
	return checkResult{name: "Secrets", status: "pass", detail: fmt.Sprintf("%s (0%o)", envPath, mode)}
}

func checkDB(cfg *config.Config) checkResult {
	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = config.DefaultDBPath()
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return checkResult{
			name: "Audit DB", status: "fail",
			detail: fmt.Sprintf("cannot open %s: %v", dbPath, err),
			repair: func() error {
				if dir := filepath.Dir(dbPath); dir != "." {
					_ = os.MkdirAll(dir, 0o700)
				}
				d, e := sql.Open("sqlite", dbPath)
				if e != nil {
					return e
				}
				return d.Close()
			},
			repairHint: "create empty database",
		}
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		return checkResult{name: "Audit DB", status: "fail", detail: fmt.Sprintf("cannot access %s: %v", dbPath, err)}
	}
	return checkResult{name: "Audit DB", status: "pass", detail: dbPath}
}

func checkKeypairs(cfg *config.Config) checkResult {
	keysDir := cfg.Identity.KeysDir
	if keysDir == "" {
		keysDir = config.DefaultKeysDir()
	}
	if len(cfg.Agents) == 0 {
		return checkResult{name: "Keypairs", status: "pass", detail: "no agents configured"}
	}
	var missing []string
	for name := range cfg.Agents {
		keyFile := filepath.Join(keysDir, name+".key")
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return checkResult{
			name: "Keypairs", status: "warn",
			detail: fmt.Sprintf("%d missing: %v", len(missing), missing),
			repair: func() error {
				_ = os.MkdirAll(keysDir, 0o700)
				for _, name := range missing {
					kp, err := identity.GenerateKeypair(name)
					if err != nil {
						return fmt.Errorf("%s: %w", name, err)
					}
					if err := kp.Save(keysDir); err != nil {
						return fmt.Errorf("saving %s: %w", name, err)
					}
				}
				return nil
			},
			repairHint: fmt.Sprintf("generate %d missing keypair(s)", len(missing)),
		}
	}
	return checkResult{name: "Keypairs", status: "pass", detail: fmt.Sprintf("%d agent(s) in %s", len(cfg.Agents), keysDir)}
}

func checkPort(cfg *config.Config) checkResult {
	bind := cfg.Server.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", bind, cfg.Server.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return checkResult{name: "Port", status: "warn", detail: fmt.Sprintf("%s in use or unavailable", addr)}
	}
	_ = ln.Close()
	return checkResult{name: "Port", status: "pass", detail: fmt.Sprintf("%s available", addr)}
}

func checkRules(cfg *config.Config) checkResult {
	scanner := engine.NewScanner(cfg.CustomRulesDir)
	defer scanner.Close()
	count := scanner.RulesCount(context.Background())
	if count == 0 {
		return checkResult{name: "Rules", status: "warn", detail: "no rules loaded"}
	}
	return checkResult{name: "Rules", status: "pass", detail: fmt.Sprintf("%d rules compiled", count)}
}
