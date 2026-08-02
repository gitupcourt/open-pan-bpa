// Package packs embeds the built-in check packs. Operators can override or
// extend them at runtime with the CLI's --packs flag.
package packs

import "embed"

//go:embed *.yaml
var FS embed.FS
