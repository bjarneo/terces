// Package rules loads, validates and versions the detection rules.
package rules

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"terces/internal/pathmatch"
)

// AllowlistFile is the name of the file that holds the global allowlist.
// All other *.yaml files in a rules directory hold rules.
const AllowlistFile = "allowlist.yaml"

// Rule is one detection rule.
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty" json:"keywords,omitempty"`
	Regex       string   `yaml:"regex" json:"regex"`
	// SecretGroup is the capture group that holds the secret. When it is
	// zero, the engine uses the first non-empty capture group. When the
	// regex has no capture groups, the engine uses the full match.
	SecretGroup int     `yaml:"secret_group,omitempty" json:"secret_group,omitempty"`
	EntropyMin  float64 `yaml:"entropy_min,omitempty" json:"entropy_min,omitempty"`
	// PairWith is the ID of a rule that must also match in the same blob.
	PairWith string `yaml:"pair_with,omitempty" json:"pair_with,omitempty"`
	Severity string `yaml:"severity" json:"severity"`
	// Path is a regex. When it is set, the rule applies only to matching paths.
	Path  string      `yaml:"path,omitempty" json:"path,omitempty"`
	Allow []RuleAllow `yaml:"allow,omitempty" json:"allow,omitempty"`

	// Compiled fields.
	Re     *regexp.Regexp `yaml:"-" json:"-"`
	PathRe *regexp.Regexp `yaml:"-" json:"-"`
	Sev    Severity       `yaml:"-" json:"-"`
	File   string         `yaml:"-" json:"-"`
}

// RuleAllow suppresses matches of one rule.
//
// With the condition "or", one matching criterion suppresses the match.
// With the condition "and", all criteria that are set must match.
type RuleAllow struct {
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Condition   string `yaml:"condition,omitempty" json:"condition,omitempty"`
	// RegexTarget selects the text that Regexes apply to: secret, match or line.
	RegexTarget string   `yaml:"regex_target,omitempty" json:"regex_target,omitempty"`
	Regexes     []string `yaml:"regexes,omitempty" json:"regexes,omitempty"`
	Stopwords   []string `yaml:"stopwords,omitempty" json:"stopwords,omitempty"`
	// Paths are regexes that apply to the file path.
	Paths []string `yaml:"paths,omitempty" json:"paths,omitempty"`

	// Compiled fields.
	And          bool             `yaml:"-" json:"-"`
	RegexesRe    []*regexp.Regexp `yaml:"-" json:"-"`
	StopwordsLow [][]byte         `yaml:"-" json:"-"`
	PathsRe      []*regexp.Regexp `yaml:"-" json:"-"`
}

// HasContentCriteria reports whether the entry has regexes or stopwords.
func (a *RuleAllow) HasContentCriteria() bool {
	return len(a.RegexesRe) > 0 || len(a.StopwordsLow) > 0
}

// MatchPath reports whether one path regex of the entry matches the path.
func (a *RuleAllow) MatchPath(p string) bool {
	for _, re := range a.PathsRe {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// Allowlist is the global allowlist. It applies to all rules.
type Allowlist struct {
	// Values are exact secret values that are never findings, such as
	// documented example keys.
	Values []string `yaml:"values,omitempty" json:"values,omitempty"`
	// Regexes apply to the secret. A match suppresses the finding.
	Regexes []string `yaml:"regexes,omitempty" json:"regexes,omitempty"`
	// Stopwords suppress a finding when the secret contains one of them.
	// The comparison ignores case.
	Stopwords []string `yaml:"stopwords,omitempty" json:"stopwords,omitempty"`
	// SkipPaths are glob patterns for paths that the scanner never reads.
	SkipPaths []string `yaml:"skip_paths,omitempty" json:"skip_paths,omitempty"`
	// SkipPathRegexes are regexes for paths that the scanner never reads.
	SkipPathRegexes []string `yaml:"skip_path_regexes,omitempty" json:"skip_path_regexes,omitempty"`
	// DowngradePaths are glob patterns. A finding in a matching path gets
	// the severity "low" instead of being suppressed.
	DowngradePaths []string `yaml:"downgrade_paths,omitempty" json:"downgrade_paths,omitempty"`

	// Compiled fields.
	ValueSet         map[string]struct{} `yaml:"-" json:"-"`
	RegexesRe        []*regexp.Regexp    `yaml:"-" json:"-"`
	StopwordsLow     [][]byte            `yaml:"-" json:"-"`
	SkipPathSet      pathmatch.Set       `yaml:"-" json:"-"`
	SkipPathRe       []*regexp.Regexp    `yaml:"-" json:"-"`
	DowngradePathSet pathmatch.Set       `yaml:"-" json:"-"`
}

// SkipPath reports whether the scanner must not read the path.
func (a *Allowlist) SkipPath(p string) bool {
	if a.SkipPathSet.Match(p) {
		return true
	}
	for _, re := range a.SkipPathRe {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// Set is a validated collection of rules plus the global allowlist.
type Set struct {
	Rules     []*Rule
	ByID      map[string]*Rule
	Allowlist *Allowlist
	Source    string
	hash      [32]byte
}

// Hash returns a SHA-256 digest of the rules and the allowlist. The digest
// changes when any rule or allowlist entry changes.
func (s *Set) Hash() [32]byte { return s.hash }

// LoadDir loads all rule files from a directory on disk.
func LoadDir(dir string) (*Set, error) {
	return LoadFS(os.DirFS(dir), dir)
}

// LoadFS loads all *.yaml files at the root of fsys. The file
// allowlist.yaml holds the global allowlist.
func LoadFS(fsys fs.FS, source string) (*Set, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read rules from %s: %w", source, err)
	}
	set := &Set{ByID: map[string]*Rule{}, Allowlist: &Allowlist{}, Source: source}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || path.Ext(name) != ".yaml" {
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		if name == AllowlistFile {
			if err := yaml.Unmarshal(data, set.Allowlist); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		var list []*Rule
		if err := yaml.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, r := range list {
			r.File = name
			set.Rules = append(set.Rules, r)
		}
	}
	if len(set.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", source)
	}
	sort.Slice(set.Rules, func(i, j int) bool { return set.Rules[i].ID < set.Rules[j].ID })

	for _, r := range set.Rules {
		if r.ID == "" {
			errs = append(errs, fmt.Errorf("%s: rule without id", r.File))
			continue
		}
		if _, dup := set.ByID[r.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate rule id %q", r.File, r.ID))
			continue
		}
		set.ByID[r.ID] = r
	}
	for _, r := range set.Rules {
		if err := r.compile(set.ByID); err != nil {
			errs = append(errs, fmt.Errorf("%s: rule %q: %w", r.File, r.ID, err))
		}
	}
	if err := set.Allowlist.compile(); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", AllowlistFile, err))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	canonical, err := json.Marshal(struct {
		Rules     []*Rule
		Allowlist *Allowlist
	}{set.Rules, set.Allowlist})
	if err != nil {
		return nil, err
	}
	set.hash = sha256.Sum256(canonical)
	return set, nil
}

func (r *Rule) compile(byID map[string]*Rule) error {
	if r.Regex == "" {
		return fmt.Errorf("regex is empty")
	}
	re, err := regexp.Compile(r.Regex)
	if err != nil {
		return fmt.Errorf("regex: %w", err)
	}
	r.Re = re
	if r.SecretGroup < 0 || r.SecretGroup > re.NumSubexp() {
		return fmt.Errorf("secret_group %d is out of range: the regex has %d groups", r.SecretGroup, re.NumSubexp())
	}
	if r.Severity == "" {
		return fmt.Errorf("severity is empty")
	}
	if r.Sev, err = ParseSeverity(r.Severity); err != nil {
		return err
	}
	if r.EntropyMin < 0 || r.EntropyMin > 8 {
		return fmt.Errorf("entropy_min %v is out of range 0 to 8", r.EntropyMin)
	}
	if r.PairWith != "" {
		if r.PairWith == r.ID {
			return fmt.Errorf("pair_with refers to the rule itself")
		}
		if _, ok := byID[r.PairWith]; !ok {
			return fmt.Errorf("pair_with refers to unknown rule %q", r.PairWith)
		}
	}
	if r.Path != "" {
		if r.PathRe, err = regexp.Compile(r.Path); err != nil {
			return fmt.Errorf("path: %w", err)
		}
	}
	for i, k := range r.Keywords {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("keyword %d is empty", i)
		}
	}
	for i := range r.Allow {
		if err := r.Allow[i].compile(); err != nil {
			return fmt.Errorf("allow entry %d: %w", i, err)
		}
	}
	return nil
}

func (a *RuleAllow) compile() error {
	switch strings.ToLower(a.Condition) {
	case "", "or":
	case "and":
		a.And = true
	default:
		return fmt.Errorf("condition %q: use or, and", a.Condition)
	}
	switch a.RegexTarget {
	case "", "secret", "match", "line":
	default:
		return fmt.Errorf("regex_target %q: use secret, match or line", a.RegexTarget)
	}
	var err error
	if a.RegexesRe, err = compileAll(a.Regexes); err != nil {
		return err
	}
	if a.PathsRe, err = compileAll(a.Paths); err != nil {
		return err
	}
	a.StopwordsLow = lowerAll(a.Stopwords)
	if !a.HasContentCriteria() && len(a.PathsRe) == 0 {
		return fmt.Errorf("entry has no regexes, stopwords or paths")
	}
	return nil
}

func (a *Allowlist) compile() error {
	a.ValueSet = make(map[string]struct{}, len(a.Values))
	for _, v := range a.Values {
		a.ValueSet[v] = struct{}{}
	}
	var err error
	if a.RegexesRe, err = compileAll(a.Regexes); err != nil {
		return fmt.Errorf("regexes: %w", err)
	}
	if a.SkipPathRe, err = compileAll(a.SkipPathRegexes); err != nil {
		return fmt.Errorf("skip_path_regexes: %w", err)
	}
	if a.SkipPathSet, err = pathmatch.CompileSet(a.SkipPaths); err != nil {
		return fmt.Errorf("skip_paths: %w", err)
	}
	if a.DowngradePathSet, err = pathmatch.CompileSet(a.DowngradePaths); err != nil {
		return fmt.Errorf("downgrade_paths: %w", err)
	}
	a.StopwordsLow = lowerAll(a.Stopwords)
	return nil
}

func compileAll(src []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(src))
	for _, s := range src {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func lowerAll(words []string) [][]byte {
	out := make([][]byte, 0, len(words))
	for _, w := range words {
		if w != "" {
			out = append(out, []byte(strings.ToLower(w)))
		}
	}
	return out
}
