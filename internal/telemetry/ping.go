// Package telemetry provides anonymous installation counting for oktsec.
//
// When oktsec starts for the first time, it sends a single anonymous HEAD
// request to count active installations. The request includes only:
//   - version (e.g. "0.11.2")
//   - os/arch (e.g. "darwin", "arm64")
//   - aggregate counts: number of agents, rules, gateway enabled, llm enabled, mode
//
// No user data, hostnames, IPs, secrets, agent names, or config details
// are transmitted. All fields are counters or booleans.
//
// Opt out: set OKTSEC_NO_TELEMETRY=1 or create ~/.oktsec/.no-telemetry
package telemetry

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

const (
	defaultPingURL = "https://oktsec.com/api/telemetry/ping"
	pingTimeout    = 5 * time.Second
	markerFile     = ".telemetry-sent"
)

// Info holds anonymous, non-identifying deployment facts.
type Info struct {
	Version  string
	Agents   int
	Rules    int
	Gateway  bool
	LLM      bool
	Enforce  bool
}

// Ping sends a single anonymous ping if this installation has not pinged before.
// It is non-blocking and best-effort: failures are silently ignored.
// Call this in a goroutine from the startup path.
func Ping(info Info, dataDir string) {
	pingWithURL(defaultPingURL, info, dataDir)
}

func pingWithURL(baseURL string, info Info, dataDir string) {
	if isDisabled() {
		return
	}

	marker := filepath.Join(dataDir, markerFile)
	if data, err := os.ReadFile(marker); err == nil {
		if string(data) == info.Version+"\n" {
			return // already pinged for this version
		}
	}

	params := url.Values{}
	params.Set("v", info.Version)
	params.Set("os", runtime.GOOS)
	params.Set("arch", runtime.GOARCH)
	params.Set("agents", strconv.Itoa(info.Agents))
	params.Set("rules", strconv.Itoa(info.Rules))
	params.Set("gw", boolStr(info.Gateway))
	params.Set("llm", boolStr(info.LLM))
	params.Set("mode", modeStr(info.Enforce))

	u := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	client := &http.Client{Timeout: pingTimeout}
	resp, err := client.Head(u)
	if err != nil {
		return // silent fail
	}
	_ = resp.Body.Close()

	// Mark as sent so we never ping again from this install
	_ = os.MkdirAll(dataDir, 0700)
	_ = os.WriteFile(marker, []byte(info.Version+"\n"), 0600)
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func modeStr(enforce bool) string {
	if enforce {
		return "enforce"
	}
	return "observe"
}

func isDisabled() bool {
	if os.Getenv("OKTSEC_NO_TELEMETRY") != "" {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	noTelemetry := filepath.Join(home, ".oktsec", ".no-telemetry")
	_, err = os.Stat(noTelemetry)
	return err == nil
}
