package rules

import "embed"

//go:embed *.yaml
var embedded embed.FS

// FS returns the embedded filesystem with oktsec's default rules.
func FS() embed.FS {
	return embedded
}
