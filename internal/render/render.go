// Package render writes findings as Markdown and as SARIF.
//
// The output holds previews and fingerprints, never a full secret. Paths
// and other repository content are untrusted, so the Markdown output puts
// them in code spans, where a renderer shows them as text.
package render

import (
	"fmt"
	"strings"

	"terces/internal/safetext"
)

// Output formats.
const (
	Text     = "text"
	JSON     = "json"
	Markdown = "markdown"
	SARIF    = "sarif"
	CSV      = "csv"
	HTML     = "html"
)

// CheckFormat returns an error when format is not in allowed.
func CheckFormat(format string, allowed ...string) error {
	for _, a := range allowed {
		if format == a {
			return nil
		}
	}
	return fmt.Errorf("--format %q: use %s", format, orList(allowed))
}

func orList(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}

// Code returns s as a Markdown code span that is safe in a table cell.
func Code(s string) string {
	if s == "" {
		return ""
	}
	s = safetext.Display(s)
	// A fence must be longer than each run of backticks in the text.
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return fence + pad + cell(s) + pad + fence
}

// cell escapes the pipe, which ends a table cell also inside a code span.
func cell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// Table writes a GitHub-flavored Markdown table. The cells must already be
// safe, for example from Code.
func Table(b *strings.Builder, headers []string, rows [][]string) {
	b.WriteString("| " + strings.Join(headers, " | ") + " |\n")
	b.WriteString("|" + strings.Repeat("---|", len(headers)) + "\n")
	for _, r := range rows {
		b.WriteString("| " + strings.Join(r, " | ") + " |\n")
	}
}
