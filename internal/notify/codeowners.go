// Package notify sends finding alerts and digests to Slack and finds the
// owners of a path from CODEOWNERS.
package notify

import (
	"bufio"
	"bytes"
	"strings"

	"terces/internal/pathmatch"
)

// CodeownersPaths are the locations that GitHub reads, in order.
var CodeownersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

type ownerRule struct {
	pattern *pathmatch.Pattern
	owners  []string
}

// Codeowners maps paths to owners.
type Codeowners struct {
	rules []ownerRule
}

// ParseCodeowners parses a CODEOWNERS file. It skips lines that it cannot
// parse, as GitHub does.
func ParseCodeowners(data []byte) *Codeowners {
	c := &Codeowners{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		p, err := pathmatch.Compile(f[0])
		if err != nil {
			continue
		}
		c.rules = append(c.rules, ownerRule{pattern: p, owners: f[1:]})
	}
	return c
}

// Owners returns the owners of a path. The last matching line wins. A
// matching line without owners means that the path has no owner.
func (c *Codeowners) Owners(path string) []string {
	if c == nil {
		return nil
	}
	for i := len(c.rules) - 1; i >= 0; i-- {
		if c.rules[i].pattern.Match(path) {
			return c.rules[i].owners
		}
	}
	return nil
}
