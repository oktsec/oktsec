package main

import (
	"fmt"
	"os"

	"github.com/oktsec/oktsec/cmd/oktsec/commands"
)

func main() {
	if err := commands.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
