package commands

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// version is set at build time via ldflags.
var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("oktsec %s\n", version)
			fmt.Printf("  go:   %s\n", runtime.Version())
			fmt.Printf("  os:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
