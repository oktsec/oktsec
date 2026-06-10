package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/oktsec/oktsec/cmd/oktsec/commands"
)

func main() {
	if err := commands.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		// Commands may tag failures with a distinct exit code (e.g.
		// `cloud sync --once`: 2 = pull/apply, 3 = report) so systemd
		// units and scripts can branch on the failing stage.
		var coded interface{ CommandExitCode() int }
		if errors.As(err, &coded) {
			os.Exit(coded.CommandExitCode())
		}
		os.Exit(1)
	}
}
