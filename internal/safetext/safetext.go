// Package safetext makes untrusted text safe to print and to store.
//
// Repository content is untrusted. A file name or an author name can hold
// control bytes, terminal escape sequences, bidirectional format
// characters or invalid UTF-8. A terminal that prints such text can hide
// a row or run an escape sequence, and Postgres rejects invalid UTF-8 in
// a text column.
package safetext

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Display returns s unchanged when s is valid UTF-8 and holds only
// printable characters. Otherwise it returns s as a quoted Go string with
// escapes, such as "caf\xe9.env". git quotes unusual paths in the same way.
// The result is always valid UTF-8 and holds no control characters.
func Display(s string) string {
	if needsQuote(s) {
		return strconv.Quote(s)
	}
	return s
}

func needsQuote(s string) bool {
	// A leading quote makes a raw value look like a quoted one.
	if strings.HasPrefix(s, `"`) {
		return true
	}
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n <= 1 {
			return true
		}
		if !unicode.IsPrint(r) {
			return true
		}
		i += n
	}
	return false
}

// Inline escapes each control character, format character and invalid
// byte in s, but keeps newlines and tabs. Use it for messages, such as an
// error with the stderr of git, where quotes around the full text do not
// help the reader.
func Inline(s string) string {
	if !needsQuote(strings.NewReplacer("\n", "", "\t", "", `"`, "").Replace(s)) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n' || r == '\t' || unicode.IsPrint(r):
			b.WriteString(s[i : i+n])
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += n
	}
	return b.String()
}
