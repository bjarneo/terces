// Package pathmatch matches slash-separated file paths against
// gitignore-style glob patterns.
//
// The rules are:
//   - A pattern without a slash matches a file or directory name at any depth.
//   - A pattern with a slash at the start or in the middle is anchored to the root.
//   - A pattern that ends with a slash matches a directory and all files below it.
//   - "*" matches any characters except "/". "?" matches one character except "/".
//   - "**" matches zero or more directories.
//   - A pattern that matches a directory also matches all paths below that directory.
package pathmatch

import (
	"fmt"
	"regexp"
	"strings"
)

// Pattern is one compiled glob pattern.
type Pattern struct {
	Glob string
	re   *regexp.Regexp
}

// Compile compiles one glob pattern.
func Compile(glob string) (*Pattern, error) {
	src, err := toRegex(glob)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %w", glob, err)
	}
	return &Pattern{Glob: glob, re: re}, nil
}

// Match reports whether the path, or one of its parent directories, matches
// the pattern.
func (p *Pattern) Match(path string) bool {
	path = strings.TrimPrefix(path, "/")
	if p.re.MatchString(path) {
		return true
	}
	for i := len(path) - 1; i > 0; i-- {
		if path[i] == '/' && p.re.MatchString(path[:i]) {
			return true
		}
	}
	return false
}

// Set is a list of patterns. A path matches the set when it matches one
// pattern.
type Set []*Pattern

// CompileSet compiles a list of glob patterns.
func CompileSet(globs []string) (Set, error) {
	set := make(Set, 0, len(globs))
	for _, g := range globs {
		p, err := Compile(g)
		if err != nil {
			return nil, err
		}
		set = append(set, p)
	}
	return set, nil
}

// Match reports whether the path matches one pattern in the set.
func (s Set) Match(path string) bool {
	for _, p := range s {
		if p.Match(path) {
			return true
		}
	}
	return false
}

func toRegex(glob string) (string, error) {
	g := strings.TrimSpace(glob)
	if g == "" {
		return "", fmt.Errorf("empty pattern")
	}
	dirOnly := strings.HasSuffix(g, "/")
	g = strings.TrimSuffix(g, "/")
	anchored := strings.HasPrefix(g, "/") || strings.Contains(g, "/")
	g = strings.TrimPrefix(g, "/")
	if g == "" {
		return "", fmt.Errorf("pattern %q matches nothing", glob)
	}

	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(g); i++ {
		c := g[i]
		switch c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				// "**" at the start or after a slash, followed by a slash
				// or by the end of the pattern.
				atStart := i == 0 || g[i-1] == '/'
				next := i + 2
				switch {
				case atStart && next < len(g) && g[next] == '/':
					b.WriteString("(?:.*/)?")
					i = next
				case atStart && next == len(g):
					b.WriteString(".*")
					i = next - 1
				default:
					b.WriteString(".*")
					i++
				}
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := strings.IndexByte(g[i+1:], ']')
			if end < 0 {
				return "", fmt.Errorf("pattern %q: unclosed character class", glob)
			}
			class := g[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i += end + 1
		case '\\':
			if i+1 < len(g) {
				i++
				b.WriteString(regexp.QuoteMeta(string(g[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if dirOnly {
		// A directory pattern matches only the files below the directory.
		b.WriteString("/.*")
	}
	b.WriteString("$")
	return b.String(), nil
}
