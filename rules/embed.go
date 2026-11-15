// Package rulesdata embeds the default rule files into the binary.
package rulesdata

import "embed"

// FS holds the *.yaml files of this directory.
//
//go:embed *.yaml
var FS embed.FS
