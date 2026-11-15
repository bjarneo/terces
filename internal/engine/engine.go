// Package engine finds secrets in file contents.
//
// The engine works on content only. It does not know the path or the
// repository of a blob. This lets the scanner cache results by blob SHA.
// ApplyPath applies the rules that depend on the path.
package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"

	"terces/internal/rules"
)

// Version identifies the engine logic. Increase it when a change to the
// engine can change the findings for the same rules. A new version makes
// the scanner rescan all blobs.
const Version = 2

// Limits for one rule in one blob. The engine keeps up to maxKeptPerRule
// different secrets. It reads up to maxRawPerRule regex matches, so that
// matches which the filters drop, and copies of a kept secret, do not hide
// a later secret. Info.Capped reports a blob that reaches a limit.
const (
	maxKeptPerRule = 200
	maxRawPerRule  = 50000
)

// Engine applies a rule set to content. It is safe for concurrent use.
type Engine struct {
	set    *rules.Set
	ac     *automaton
	kwRule []int
	kwLen  []int
	always []int
	// pad is, for each rule, the window size on each side of a keyword hit.
	// It is 0 when the rule runs on the full text.
	pad []int
}

// Match is one secret that the engine found in content.
type Match struct {
	Rule *rules.Rule
	// Secret is the plaintext secret. Hash it and drop it. Never store it,
	// print it or log it.
	Secret []byte
	// Line is the 1-based line of the secret in the blob. For a decoded
	// secret, it is the line of the encoded text.
	Line int
	// Decoded is "base64" or "url" when the secret was inside encoded text.
	Decoded string
	// PathAllow lists entries of Rule.Allow whose content criteria match.
	// The match is suppressed when the path also matches one of them.
	PathAllow []int
}

// Candidate is a regex match plus the reason the engine dropped it.
// Explain returns candidates for rule development.
type Candidate struct {
	Match
	Entropy float64
	// Dropped is empty when the engine keeps the match.
	Dropped string
}

// New builds an engine for a rule set.
func New(set *rules.Set) *Engine {
	e := &Engine{set: set, pad: make([]int, len(set.Rules))}
	var keywords []string
	for i, r := range set.Rules {
		if len(r.Keywords) == 0 {
			e.always = append(e.always, i)
			continue
		}
		// Each match contains a keyword, so each match lies within n
		// bytes of a keyword hit, where n is the longest match of the
		// regex. One more byte keeps each valid match off the window edge.
		if n := matchLimit(r.Re.String(), r.Keywords); n >= 0 {
			e.pad[i] = n + 1
		}
		for _, k := range r.Keywords {
			keywords = append(keywords, k)
			e.kwRule = append(e.kwRule, i)
			e.kwLen = append(e.kwLen, len(k))
		}
	}
	e.ac = newAutomaton(keywords)
	return e
}

// Rules returns the rule set of the engine.
func (e *Engine) Rules() *rules.Set { return e.set }

// CacheVersion returns the version for the blob cache. It changes when the
// rules, the global allowlist, the engine logic or the size limit change.
func (e *Engine) CacheVersion(maxBlobSize int64) int64 {
	h := sha256.New()
	sum := e.set.Hash()
	h.Write(sum[:])
	fmt.Fprintf(h, "engine=%d max=%d", Version, maxBlobSize)
	v := binary.BigEndian.Uint64(h.Sum(nil)[:8])
	return int64(v & 0x7fffffffffffffff)
}

// SkipPath reports whether the scanner must not read the path.
func (e *Engine) SkipPath(p string) bool {
	return e.set.Allowlist.SkipPath(p)
}

// Scan returns the secrets in content.
func (e *Engine) Scan(content []byte) []Match {
	m, _ := e.ScanStats(content)
	return m
}

// Info reports what one scan of a blob did.
type Info struct {
	// Hit is true when the keyword prefilter selected one or more rules.
	Hit bool
	// Capped is true when a rule reached the match limit, so the blob can
	// hold more secrets than the scan reports.
	Capped bool
}

// ScanStats returns the secrets in content and what the scan did.
func (e *Engine) ScanStats(content []byte) ([]Match, Info) {
	cands, info := e.scan(content, false)
	if len(cands) == 0 {
		return nil, info
	}
	out := make([]Match, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Match)
	}
	return out, info
}

// Explain returns all regex matches of one rule in content, with the
// reason for each dropped match. It runs all rules, because pairing
// depends on the other rules.
func (e *Engine) Explain(ruleID string, content []byte) ([]Candidate, error) {
	r, ok := e.set.ByID[ruleID]
	if !ok {
		return nil, fmt.Errorf("unknown rule %q", ruleID)
	}
	var out []Candidate
	cands, _ := e.scan(content, true)
	for _, c := range cands {
		if c.Rule == r {
			out = append(out, c)
		}
	}
	return out, nil
}

// ApplyPath applies the path-dependent parts of the rules to a match at a
// path. It returns the severity for the path, or a reason when the match
// does not apply to the path.
func (e *Engine) ApplyPath(ruleID string, pathAllow []int, sev rules.Severity, p string) (rules.Severity, string) {
	r, ok := e.set.ByID[ruleID]
	if !ok {
		return sev, "rule no longer exists"
	}
	if r.PathRe != nil && !r.PathRe.MatchString(p) {
		return sev, "rule applies to other paths"
	}
	for _, k := range pathAllow {
		if k >= 0 && k < len(r.Allow) && r.Allow[k].MatchPath(p) {
			return sev, "rule allowlist path"
		}
	}
	if e.set.Allowlist.DowngradePathSet.Match(p) {
		sev = rules.SeverityLow
	}
	return sev, ""
}

func (e *Engine) scan(data []byte, trace bool) ([]Candidate, Info) {
	lines := &lineIndex{data: data}
	var out []Candidate
	var info Info
	e.scanText(data, 0, "", lines, trace, &out, &info)
	for _, seg := range decodeSegments(data) {
		e.scanText(seg.data, seg.offset, seg.kind, lines, trace, &out, &info)
	}
	if len(out) == 0 {
		return nil, info
	}

	// Pairing: a rule with pair_with applies only when its partner also
	// has a kept match in the same blob.
	present := map[string]bool{}
	for _, c := range out {
		if c.Dropped == "" {
			present[c.Rule.ID] = true
		}
	}
	// Dedupe: keep the first match of each secret for each rule.
	seen := map[string]bool{}
	for i := range out {
		c := &out[i]
		if c.Dropped != "" {
			continue
		}
		if c.Rule.PairWith != "" && !present[c.Rule.PairWith] {
			c.Dropped = "unpaired: needs a match of " + c.Rule.PairWith
			continue
		}
		key := c.Rule.ID + "\x00" + string(c.Secret)
		if seen[key] {
			c.Dropped = "duplicate"
			continue
		}
		seen[key] = true
	}
	if trace {
		return out, info
	}
	kept := out[:0]
	for _, c := range out {
		if c.Dropped == "" {
			kept = append(kept, c)
		}
	}
	return kept, info
}

// scanText scans one text. For decoded text, base is the offset of the
// encoded text in the blob. It adds to info.
func (e *Engine) scanText(text []byte, base int, kind string, lines *lineIndex, trace bool, out *[]Candidate, info *Info) {
	cand := make([]bool, len(e.set.Rules))
	var near [][]span
	hit := false
	e.ac.scan(text, func(k int32, end int) {
		i := e.kwRule[k]
		cand[i] = true
		hit = true
		if pad := e.pad[i]; pad > 0 {
			if near == nil {
				near = make([][]span, len(e.set.Rules))
			}
			w := span{max(0, end-e.kwLen[k]-pad), min(len(text), end+pad)}
			if n := len(near[i]); n > 0 && w.start <= near[i][n-1].end {
				last := &near[i][n-1]
				last.start, last.end = min(last.start, w.start), max(last.end, w.end)
			} else {
				near[i] = append(near[i], w)
			}
		}
	})
	for _, i := range e.always {
		cand[i] = true
	}
	if hit {
		info.Hit = true
	}
	if !hit && len(e.always) == 0 {
		return
	}
	for i, ok := range cand {
		if !ok {
			continue
		}
		r := e.set.Rules[i]
		var locs [][]int
		if near != nil && len(near[i]) > 0 {
			locs = findNear(r.Re, text, near[i])
		} else {
			locs = r.Re.FindAllSubmatchIndex(text, maxRawPerRule)
		}
		if len(locs) >= maxRawPerRule {
			info.Capped = true
		}
		// kept holds the different secrets that this rule keeps. A copy of
		// a kept secret does not count toward the limit.
		var kept map[string]bool
		for _, loc := range locs {
			if len(kept) >= maxKeptPerRule {
				info.Capped = true
				break
			}
			start, end := secretSpan(r, loc)
			if start < 0 || end <= start {
				continue
			}
			secret := text[start:end]
			off := start
			if kind != "" {
				off = base
			}
			c := Candidate{
				Match: Match{
					Rule:    r,
					Secret:  bytes.Clone(secret),
					Line:    lines.line(off),
					Decoded: kind,
				},
				Entropy: entropy(secret),
			}
			c.Dropped, c.PathAllow = e.filter(r, text, loc, secret, c.Entropy)
			if c.Dropped == "" {
				if kept == nil {
					kept = map[string]bool{}
				}
				kept[string(secret)] = true
			} else if !trace {
				continue
			}
			*out = append(*out, c)
		}
	}
}

// findNear returns the matches of re in the windows around the keyword
// hits. A regex runs in time linear in its input, so a large blob with a
// small number of keyword hits costs much less than a full scan. The result
// is the same as for the full text: each match contains a keyword and is
// not longer than the window pad. A match that touches the edge of a window
// breaks this contract, so the function then scans the full text.
func findNear(re *regexp.Regexp, text []byte, ws []span) [][]int {
	ws = windows(ws, 0, len(text))
	total := 0
	for _, w := range ws {
		total += w.end - w.start
	}
	if total*2 >= len(text) {
		return re.FindAllSubmatchIndex(text, maxRawPerRule)
	}
	var out [][]int
	for _, w := range ws {
		n := maxRawPerRule - len(out)
		if n <= 0 {
			break
		}
		for _, loc := range re.FindAllSubmatchIndex(text[w.start:w.end], n) {
			if (loc[0] == 0 && w.start > 0) || (loc[1] == w.end-w.start && w.end < len(text)) {
				return re.FindAllSubmatchIndex(text, maxRawPerRule)
			}
			for j := range loc {
				if loc[j] >= 0 {
					loc[j] += w.start
				}
			}
			out = append(out, loc)
		}
	}
	return out
}

// secretSpan returns the span of the secret inside one regex match.
func secretSpan(r *rules.Rule, loc []int) (int, int) {
	groups := len(loc)/2 - 1
	switch {
	case r.SecretGroup > 0 && r.SecretGroup <= groups:
		return loc[2*r.SecretGroup], loc[2*r.SecretGroup+1]
	case groups > 0:
		for g := 1; g <= groups; g++ {
			if loc[2*g] >= 0 && loc[2*g+1] > loc[2*g] {
				return loc[2*g], loc[2*g+1]
			}
		}
		return -1, -1
	default:
		return loc[0], loc[1]
	}
}

// filter applies the entropy check and the allowlists. It returns a reason
// when the match is dropped, and the rule allowlist entries that still
// need a path check.
func (e *Engine) filter(r *rules.Rule, text []byte, loc []int, secret []byte, ent float64) (string, []int) {
	if r.EntropyMin > 0 && ent < r.EntropyMin {
		return fmt.Sprintf("entropy %.2f is below %.2f", ent, r.EntropyMin), nil
	}
	al := e.set.Allowlist
	if _, ok := al.ValueSet[string(secret)]; ok {
		return "global allowlist: known test value", nil
	}
	for _, re := range al.RegexesRe {
		if re.Match(secret) {
			return "global allowlist: regex " + re.String(), nil
		}
	}
	lower := bytes.ToLower(secret)
	for _, w := range al.StopwordsLow {
		if bytes.Contains(lower, w) {
			return "global allowlist: stopword " + string(w), nil
		}
	}

	var pathAllow []int
	for k := range r.Allow {
		a := &r.Allow[k]
		target := secret
		switch a.RegexTarget {
		case "match":
			target = text[loc[0]:loc[1]]
		case "line":
			target = lineAround(text, loc[0], loc[1])
		}
		regexHit := false
		for _, re := range a.RegexesRe {
			if re.Match(target) {
				regexHit = true
				break
			}
		}
		stopHit := false
		for _, w := range a.StopwordsLow {
			if bytes.Contains(lower, w) {
				stopHit = true
				break
			}
		}
		hasPaths := len(a.PathsRe) > 0
		if !a.And {
			if regexHit || stopHit {
				return "rule allowlist", nil
			}
			if hasPaths {
				pathAllow = append(pathAllow, k)
			}
			continue
		}
		contentOK := (len(a.RegexesRe) == 0 || regexHit) && (len(a.StopwordsLow) == 0 || stopHit)
		if !contentOK {
			continue
		}
		if !hasPaths {
			return "rule allowlist", nil
		}
		pathAllow = append(pathAllow, k)
	}
	return "", pathAllow
}

// maxLineContext limits the line that an allowlist entry with
// regex_target: line sees to this number of bytes on each side of the
// match. Without the limit, a minified file with one long line and many
// candidates costs time in the square of the line length.
const maxLineContext = 4 << 10

// lineAround returns the lines that contain text[start:end], up to
// maxLineContext bytes on each side of the match.
func lineAround(text []byte, start, end int) []byte {
	lo := max(0, start-maxLineContext)
	s := lo
	if i := bytes.LastIndexByte(text[lo:start], '\n'); i >= 0 {
		s = lo + i + 1
	}
	hi := min(len(text), end+maxLineContext)
	e := hi
	if i := bytes.IndexByte(text[end:hi], '\n'); i >= 0 {
		e = end + i
	}
	return text[s:e]
}

// lineIndex converts byte offsets to line numbers. It builds the index on
// first use, because most blobs have no matches.
type lineIndex struct {
	data     []byte
	newlines []int
	built    bool
}

func (l *lineIndex) line(off int) int {
	if !l.built {
		for i, b := range l.data {
			if b == '\n' {
				l.newlines = append(l.newlines, i)
			}
		}
		l.built = true
	}
	return sort.SearchInts(l.newlines, off) + 1
}
