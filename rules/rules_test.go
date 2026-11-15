package rulesdata_test

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"

	"terces/internal/engine"
	"terces/internal/rules"
	"terces/internal/testsecret"
	rulesdata "terces/rules"
)

type fixture struct {
	Rule     string   `yaml:"rule"`
	Path     string   `yaml:"path"`
	Positive []string `yaml:"positive"`
	Negative []string `yaml:"negative"`
}

func loadEngine(t *testing.T) *engine.Engine {
	t.Helper()
	set, err := rules.LoadFS(rulesdata.FS, "built-in")
	if err != nil {
		t.Fatalf("load built-in rules: %v", err)
	}
	return engine.New(set)
}

func findingsOf(e *engine.Engine, rule, path, content string) int {
	n := 0
	for _, m := range e.Scan([]byte(content)) {
		if m.Rule.ID != rule {
			continue
		}
		if _, reason := e.ApplyPath(m.Rule.ID, m.PathAllow, m.Rule.Sev, path); reason == "" {
			n++
		}
	}
	return n
}

func TestFixtures(t *testing.T) {
	e := loadEngine(t)
	files, err := filepath.Glob("testdata/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixture files: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var fixtures []fixture
		if err := yaml.Unmarshal(data, &fixtures); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, fx := range fixtures {
			if _, ok := e.Rules().ByID[fx.Rule]; !ok {
				t.Errorf("%s: unknown rule %q", file, fx.Rule)
				continue
			}
			path := fx.Path
			if path == "" {
				path = "config/app.conf"
			}
			for i, tmpl := range fx.Positive {
				// Run each template more than one time, because the
				// random part changes.
				for run := 0; run < 5; run++ {
					if findingsOf(e, fx.Rule, path, testsecret.Expand(tmpl)) == 0 {
						t.Errorf("%s: %s positive %d: no finding", file, fx.Rule, i)
						break
					}
				}
			}
			for i, tmpl := range fx.Negative {
				for run := 0; run < 5; run++ {
					if findingsOf(e, fx.Rule, path, testsecret.Expand(tmpl)) != 0 {
						t.Errorf("%s: %s negative %d: unexpected finding", file, fx.Rule, i)
						break
					}
				}
			}
		}
	}
}

func TestBuiltInRulesLoad(t *testing.T) {
	e := loadEngine(t)
	if n := len(e.Rules().Rules); n < 200 {
		t.Errorf("only %d built-in rules: is rules/gitleaks.yaml missing?", n)
	}
	for _, r := range e.Rules().Rules {
		if len(r.Keywords) == 0 {
			t.Errorf("rule %s has no keywords: it runs on every blob", r.ID)
		}
	}
}

func TestDowngradePath(t *testing.T) {
	e := loadEngine(t)
	content := testsecret.PrivateKey()
	ms := e.Scan([]byte(content))
	if len(ms) == 0 {
		t.Fatal("no match for a private key")
	}
	sev, reason := e.ApplyPath(ms[0].Rule.ID, ms[0].PathAllow, ms[0].Rule.Sev, "test/fixtures/key.pem")
	if reason != "" || sev != rules.SeverityLow {
		t.Errorf("fixture path: severity %v, reason %q, want low and no reason", sev, reason)
	}
	sev, _ = e.ApplyPath(ms[0].Rule.ID, ms[0].PathAllow, ms[0].Rule.Sev, "deploy/key.pem")
	if sev != rules.SeverityCritical {
		t.Errorf("normal path: severity %v, want critical", sev)
	}
}
