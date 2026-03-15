package static

import "embed"

//go:embed *.js *.css fonts/*.woff2
var FS embed.FS
