package commands

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// printBanner is the static (non-TUI) startup banner the operator
// sees when running oktsec without an interactive terminal. It must
// not carry the universal-visibility wording the dashboard UX spec
// hard-bans. The TUI tagline and the dashboard templates already
// have regression coverage for the same contract; this test extends
// the public-artifact sweep to the terminal-output path so the next
// sweep run cannot miss it.
func TestPrintBanner_DoesNotOverclaim(t *testing.T) {
	// printBanner writes to os.Stdout via fmt.Print*, so we swap
	// stdout for a pipe, capture, and restore. The package already
	// has a captureStdout helper for tokens_test.go but it takes a
	// func(*os.File) and the caller writes to that file directly;
	// printBanner does not accept a writer parameter so we inline
	// the capture here rather than refactor the production code
	// path just for testability.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.Bytes()
	}()

	printBanner(&config.Config{
		Server: config.ServerConfig{Port: 8080},
	}, "12345678")

	_ = w.Close()
	os.Stdout = old
	out := string(<-done)

	plain := stripBannerANSI(out)
	lower := strings.ToLower(plain)

	for _, banned := range []string{
		"see everything",
		"sees everything",
		"sees all",
		"every tool call your ai agents make",
		"every tool call scanned",
		"all ai agent tool calls",
		"complete coverage",
		"complete protection",
		"fully protected",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("startup banner contains banned phrase %q\nbanner output:\n%s", banned, plain)
		}
	}

	// Positive direction: the qualified replacement copy must be
	// present, so a future revert of the wording fix fires this
	// test too.
	if !strings.Contains(plain, "Visibility into the tool calls your AI agents route through Oktsec") {
		t.Errorf("startup banner missing the qualified visibility tagline; got:\n%s", plain)
	}
}

// stripBannerANSI removes ANSI SGR escape sequences (the only kind
// the banner emits via the fatih/color package) so banned-phrase
// assertions don't have to thread through color codes.
func stripBannerANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == 0x1b && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			if j < len(s) {
				j++ // include the final byte
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
