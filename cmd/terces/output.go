package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"terces/internal/safetext"
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type table struct {
	tw *tabwriter.Writer
}

func newTable(w io.Writer, headers ...string) *table {
	t := &table{tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)}
	t.row(headers...)
	return t
}

func (t *table) row(cols ...string) {
	for i, c := range cols {
		// Tabs and newlines in values break the layout. Other control
		// bytes in repository content can hide a row or change the
		// terminal, so they get escapes.
		cols[i] = safetext.Inline(strings.NewReplacer("\t", " ", "\n", " ").Replace(c))
	}
	fmt.Fprintln(t.tw, strings.Join(cols, "\t"))
}

func (t *table) flush() error { return t.tw.Flush() }
