package engine

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxWindowPad is the largest match length in bytes for which the engine
// runs a regex only near the keyword hits. A rule whose matches can be
// longer runs on the full text.
const maxWindowPad = 16 << 10

// greedyRun is the length in bytes that a greedy repeat without an upper
// bound, such as x+ or x{11,}, counts as. A longer run usually reaches the
// edge of the window, and findNear then scans the full text. Otherwise the
// engine can miss a match with a run of more than 4 KB. A lazy repeat such
// as x+? stops early instead, so a rule with one runs on the full text.
const greedyRun = 4 << 10

// matchLimit returns the largest number of bytes in one match of expr. It
// returns -1 when the rule must run on the full text: the length has no
// limit, or a match can occur without one of the keywords.
func matchLimit(expr string, keywords []string) int {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return -1
	}
	re = re.Simplify()
	lower := make([]string, len(keywords))
	for i, k := range keywords {
		lower[i] = strings.ToLower(k)
	}
	if !mustContain(re, lower) {
		return -1
	}
	n := maxLen(re)
	if n < 0 || n > maxWindowPad {
		return -1
	}
	return n
}

// maxLen returns the largest number of bytes that re can match, or -1 when
// the length has no limit.
func maxLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				n += foldLen(r)
			} else {
				n += runeLen(r)
			}
		}
		return n
	case syntax.OpCharClass:
		// Rune holds pairs of low and high bounds. The high bound has the
		// longest encoding in each pair.
		n := 0
		for i := 1; i < len(re.Rune); i += 2 {
			n = max(n, runeLen(re.Rune[i]))
		}
		return n
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return maxLen(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		if re.Flags&syntax.NonGreedy != 0 || maxLen(re.Sub[0]) < 0 {
			return -1
		}
		return greedyRun
	case syntax.OpRepeat:
		if re.Max < 0 {
			// Simplify rewrites x{n,} as n-1 copies of x plus x+, so
			// this case does not occur.
			return -1
		}
		n := maxLen(re.Sub[0])
		if n < 0 || (n > 0 && re.Max > maxWindowPad/n+1) {
			return -1
		}
		return n * re.Max
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			m := maxLen(s)
			if m < 0 {
				return -1
			}
			n += m
			if n > maxWindowPad {
				return -1
			}
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			m := maxLen(s)
			if m < 0 {
				return -1
			}
			n = max(n, m)
		}
		return n
	}
	return -1
}

// mustContain reports whether each match of re contains one of the
// keywords, without case. A false result can be wrong, which only costs
// speed: the rule then runs on the full text.
func mustContain(re *syntax.Regexp, keywords []string) bool {
	lp := literalPaths{keywords: keywords}
	for _, p := range lp.of(re) {
		if p != done {
			return false
		}
	}
	return true
}

const (
	// gap marks text in a path that is not a known literal.
	gap = "\x00"
	// done is a path that contains a keyword. Text before or after it
	// cannot remove the keyword.
	done = "\x01"
	// maxPaths limits the number of paths for one part of a regex.
	maxPaths = 256
)

// literalPaths computes the lower-case literal text of each way that a
// regex can match. Text that is not a fixed literal is a gap. Each match
// contains, without gaps, the literal parts of one of the paths.
type literalPaths struct {
	keywords []string
}

func (lp literalPaths) of(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return lp.norm([]string{strings.ToLower(string(re.Rune))})
	case syntax.OpCharClass:
		if s, ok := oneLetter(re); ok {
			return []string{s}
		}
		return []string{gap}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}
	case syntax.OpCapture:
		return lp.of(re.Sub[0])
	case syntax.OpQuest:
		return lp.norm(append(lp.of(re.Sub[0]), ""))
	case syntax.OpPlus:
		// The first copy joins the text before it. The text after it is
		// not known.
		return lp.concat(lp.of(re.Sub[0]), []string{gap})
	case syntax.OpRepeat:
		if re.Min > 0 {
			return lp.concat(lp.of(re.Sub[0]), []string{gap})
		}
		return []string{gap}
	case syntax.OpAlternate:
		var out []string
		for _, s := range re.Sub {
			out = lp.norm(append(out, lp.of(s)...))
		}
		return out
	case syntax.OpConcat:
		out := []string{""}
		for _, s := range re.Sub {
			out = lp.concat(out, lp.of(s))
		}
		return out
	}
	return []string{gap}
}

// concat joins each path of a with each path of b.
func (lp literalPaths) concat(a, b []string) []string {
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			if x == done || y == done {
				out = append(out, done)
			} else {
				out = append(out, x+y)
			}
		}
	}
	return lp.norm(out)
}

// norm merges adjacent gaps, marks paths with a keyword as done and drops
// duplicates. Too many paths collapse into one gap, which makes
// mustContain return false.
func (lp literalPaths) norm(ps []string) []string {
	seen := make(map[string]bool, len(ps))
	out := ps[:0]
	for _, p := range ps {
		for strings.Contains(p, gap+gap) {
			p = strings.ReplaceAll(p, gap+gap, gap)
		}
		if p != done {
			for _, part := range strings.Split(p, gap) {
				if containsAny(part, lp.keywords) {
					p = done
					break
				}
			}
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) > maxPaths {
		return []string{gap}
	}
	return out
}

// oneLetter returns the lower-case letter of a class that matches one
// letter in both cases, such as [Aa].
func oneLetter(re *syntax.Regexp) (string, bool) {
	var first rune = -1
	for i := 0; i+1 < len(re.Rune); i += 2 {
		if re.Rune[i+1]-re.Rune[i] > 4 {
			return "", false
		}
		for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
			l := unicode.ToLower(r)
			if first >= 0 && l != first {
				return "", false
			}
			first = l
		}
	}
	if first < 0 {
		return "", false
	}
	return string(first), true
}

func containsAny(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func runeLen(r rune) int {
	if n := utf8.RuneLen(r); n > 0 {
		return n
	}
	return utf8.UTFMax
}

// foldLen returns the longest encoding of r and of the runes that are
// equal to r without case. In Go, (?i)k also matches the Kelvin sign.
func foldLen(r rune) int {
	n := runeLen(r)
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		n = max(n, runeLen(f))
	}
	return n
}

// span is a byte range [start, end) in a text.
type span struct{ start, end int }

// windows returns the merged ranges that extend pad bytes on each side of
// each keyword hit, clamped to [0, size).
func windows(hits []span, pad, size int) []span {
	ws := make([]span, 0, len(hits))
	for _, h := range hits {
		ws = append(ws, span{max(0, h.start-pad), min(size, h.end+pad)})
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i].start < ws[j].start })
	out := ws[:0]
	for _, w := range ws {
		if n := len(out); n > 0 && w.start <= out[n-1].end {
			out[n-1].end = max(out[n-1].end, w.end)
			continue
		}
		out = append(out, w)
	}
	return out
}
