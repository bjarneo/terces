// Package migrations embeds the SQL migrations into the binary.
package migrations

import "embed"

// FS holds the *.sql files of this directory. The store applies them in
// file name order.
//
//go:embed *.sql
var FS embed.FS
