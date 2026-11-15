// Package repoconfig reads the per-repository file .terces.yaml.
//
// The file lists fingerprints to ignore. It never contains raw secret values:
//
//	ignore:
//	  - fingerprint: 3f2a9c1b04de5f6a7b8c9d0e1f2a3b4c
//	    note: fake key in the API docs
//	  - 9a8b7c6d5e4f3a2b1c0d9e8f
package repoconfig

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// FileName is the name of the file at the root of a repository.
const FileName = ".terces.yaml"

// MaxSize is the largest file that Parse accepts.
const MaxSize = 1 << 20

// MinPrefixLen is the minimum length of a fingerprint prefix in hex
// characters. A shorter prefix can match unrelated secrets.
const MinPrefixLen = 16

// Config is the parsed content of .terces.yaml.
type Config struct {
	Ignore []Entry `yaml:"ignore"`
}

// Entry is one ignored fingerprint.
type Entry struct {
	Fingerprint string `yaml:"fingerprint"`
	Note        string `yaml:"note,omitempty"`
}

// UnmarshalYAML accepts an entry as a plain string or as a mapping.
func (e *Entry) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		e.Fingerprint = n.Value
		return nil
	}
	type plain Entry
	return n.Decode((*plain)(e))
}

var yamlLine = regexp.MustCompile(`line (\d+)`)

// Parse parses and validates the file content. An error names the line,
// but never the content: a hostile file can be a link to a key file.
func Parse(data []byte) (*Config, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%s: the file is larger than 1 MB", FileName)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			return nil, fmt.Errorf("%s: invalid YAML at line %s", FileName, m[1])
		}
		return nil, fmt.Errorf("%s: invalid YAML", FileName)
	}
	for i := range c.Ignore {
		fp := strings.ToLower(strings.TrimSpace(c.Ignore[i].Fingerprint))
		if len(fp) < MinPrefixLen {
			return nil, fmt.Errorf("%s: ignore entry %d: use %d or more hex characters", FileName, i, MinPrefixLen)
		}
		if _, err := hex.DecodeString(fp[:len(fp)/2*2]); err != nil {
			return nil, fmt.Errorf("%s: ignore entry %d: the fingerprint is not hex", FileName, i)
		}
		c.Ignore[i].Fingerprint = fp
	}
	return &c, nil
}

// Ignored reports whether the config ignores a fingerprint. A nil config
// ignores nothing.
func (c *Config) Ignored(fp []byte) bool {
	if c == nil || len(c.Ignore) == 0 {
		return false
	}
	h := hex.EncodeToString(fp)
	for _, e := range c.Ignore {
		if strings.HasPrefix(h, e.Fingerprint) {
			return true
		}
	}
	return false
}
