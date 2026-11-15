package engine

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp/syntax"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"terces/internal/rules"
	"terces/internal/testsecret"
	rulesdata "terces/rules"
)

func TestMatchLimit(t *testing.T) {
	cases := map[string]int{
		`abc`:              3,
		`(?i)k`:            3, // the Kelvin sign is 3 bytes
		`a{2,5}`:           5,
		`[a-z]{0,50}?x`:    51,
		`\bkey\b`:          3,
		`a|bcd`:            3,
		`é`:                2,
		`a+`:               greedyRun,
		`a{11,}`:           10 + greedyRun,
		`a+?`:              -1,
		`[\s\S]{64,}?END`:  -1,
		`(?:a{1000}){100}`: -1,
	}
	for expr, want := range cases {
		if got := matchLimit(expr, []string{"a", "b", "e", "k", "x", "é"}); got != want {
			t.Errorf("matchLimit(%q) = %d, want %d", expr, got, want)
		}
	}
}

func TestMustContain(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{`(?i)tok_[a-z]{20}`, true},
		{`(?-i:[Aa]pi|API)_key`, true},
		{`\b(?:sgp_[a-f0-9]{40}|[a-f0-9]{40})\b`, false},
		{`(?:x_)?tok_`, true},
		{`(?:tok_)?[a-z]{20}`, false},
		{`(?:tok_)+y`, true},
		{`(?:tok_)*y`, false},
		{`t(?:o)k_`, true},
		{`passw(?:or)?d`, true},
		{`A(?:KIA|3T[A-Z0-9])`, true},
		{`(?:a|b)(?:c|d)`, false},
	}
	for _, c := range cases {
		re, err := syntax.Parse(c.expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if got := mustContain(re.Simplify(), []string{"tok_", "api", "sgp_", "passwd", "password", "akia", "a3t"}); got != c.want {
			t.Errorf("mustContain(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestWindows(t *testing.T) {
	got := windows([]span{{50, 60}, {10, 20}, {18, 30}, {90, 95}}, 5, 100)
	want := []span{{5, 35}, {45, 65}, {85, 100}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("windows = %v, want %v", got, want)
	}
}

// TestWindowedScanMatchesFullScan checks that a scan near the keyword hits
// finds the same matches as a scan of the full text, for all built-in rules.
func TestWindowedScanMatchesFullScan(t *testing.T) {
	set, err := rules.LoadFS(rulesdata.FS, "built-in")
	if err != nil {
		t.Fatal(err)
	}
	windowed := New(set)
	full := New(set)
	clear(full.pad)

	positives := append(fixturePositives(t), "SOURCEGRAPH=sgp_{{rand:a-f0-9:40}}")
	rng := rand.New(rand.NewPCG(7, 11))
	filler := func() string {
		switch rng.IntN(7) {
		case 0:
			return strings.Repeat("x", rng.IntN(9000))
		case 1:
			return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("config key=value\n", rng.IntN(400))))
		case 2:
			return "func main() { key := os.Getenv(\"API_KEY\"); _ = key }"
		case 3:
			return strings.Repeat("abcdef0123456789", rng.IntN(600))
		case 4:
			return "token: " + testsecret.Rand("a-z0-9", 20+rng.IntN(5000))
		case 5:
			// A bare hex string far from a keyword. One rule matches it
			// anywhere in a blob that has its keyword.
			return strings.Repeat("filler line\n", 300) + "RANDOM=" + testsecret.Rand("a-f0-9", 40)
		default:
			return ""
		}
	}
	for round := 0; round < 8; round++ {
		var b strings.Builder
		for i := 0; i < 30; i++ {
			b.WriteString(filler())
			sep := []string{"\n", " ", "", "\n\n"}[rng.IntN(4)]
			b.WriteString(sep)
			b.WriteString(testsecret.Expand(positives[rng.IntN(len(positives))]))
			b.WriteString(sep)
		}
		text := []byte(b.String())
		got, want := summary(windowed.Scan(text)), summary(full.Scan(text))
		if want == "" {
			t.Fatalf("round %d: no matches, so the test checks nothing", round)
		}
		if got != want {
			t.Fatalf("round %d: windowed scan differs from full scan\nwindowed:\n%s\nfull:\n%s", round, got, want)
		}
	}
}

func summary(ms []Match) string {
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "%s line %d len %d %s\n", m.Rule.ID, m.Line, len(m.Secret), m.Decoded)
	}
	return b.String()
}

func fixturePositives(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("../../rules/testdata/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixture files: %v", err)
	}
	var out []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fixtures []struct {
			Positive []string `yaml:"positive"`
		}
		if err := yaml.Unmarshal(data, &fixtures); err != nil {
			t.Fatal(err)
		}
		for _, fx := range fixtures {
			out = append(out, fx.Positive...)
		}
	}
	return out
}
