package rules

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadValidation(t *testing.T) {
	cases := map[string]string{
		"duplicate id":       "- {id: a, regex: x, severity: low}\n- {id: a, regex: y, severity: low}",
		"bad regex":          "- {id: a, regex: '(', severity: low}",
		"unknown severity":   "- {id: a, regex: x, severity: urgent}",
		"unknown pair_with":  "- {id: a, regex: x, severity: low, pair_with: b}",
		"group out of range": "- {id: a, regex: '(x)', secret_group: 2, severity: low}",
		"empty allow entry":  "- {id: a, regex: x, severity: low, allow: [{condition: and}]}",
	}
	for name, doc := range cases {
		_, err := LoadFS(fstest.MapFS{"r.yaml": {Data: []byte(doc)}}, "test")
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestConvertGitleaks(t *testing.T) {
	toml := `
title = "test"
[allowlist]
paths = ['''vendor/''']

[[rules]]
id = "demo-token"
description = "Demo token"
regex = '''\b(demo_[a-z0-9]{20})\b'''
entropy = 3
keywords = ["demo_"]
[[rules.allowlists]]
regexTarget = "line"
regexes = ['''EXAMPLE''']

[[rules]]
id = "only-path"
path = '''\.p12$'''

[[rules]]
id = "some-private-key"
regex = '''-----BEGIN KEY-----'''
keywords = ["-----begin"]

[[rules]]
id = "skip-me"
regex = '''x'''
`
	out, notes, err := ConvertGitleaks([]byte(toml), ConvertOptions{Exclude: []string{"skip-me"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 2 {
		t.Errorf("notes = %q, want 2", notes)
	}
	set, err := LoadFS(fstest.MapFS{"g.yaml": {Data: out}}, "test")
	if err != nil {
		t.Fatalf("converted rules do not load: %v\n%s", err, out)
	}
	r := set.ByID["demo-token"]
	if r == nil || r.EntropyMin != 3 || len(r.Allow) != 1 || r.Allow[0].RegexTarget != "line" || r.Sev != SeverityHigh {
		t.Errorf("demo-token: %+v", r)
	}
	if set.ByID["some-private-key"].Sev != SeverityCritical {
		t.Error("a private key rule must be critical")
	}
	if !strings.Contains(string(out), "THIRD_PARTY.md") {
		t.Error("the output must point to the license notice")
	}
}
