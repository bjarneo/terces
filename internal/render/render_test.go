package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"terces/internal/rules"
	"terces/internal/scanner"
)

func TestCode(t *testing.T) {
	cases := map[string]string{
		"src/app.go":  "`src/app.go`",
		"a|b":         "`a\\|b`",
		"x`y":         "``x`y``",
		"`edge":       "`` `edge ``",
		"esc\x1b[2Kx": "`\"esc\\x1b[2Kx\"`",
		"":            "",
	}
	for in, want := range cases {
		if got := Code(in); got != want {
			t.Errorf("Code(%q) = %s, want %s", in, got, want)
		}
	}
}

func testFindings() []scanner.Finding {
	return []scanner.Finding{
		{Fingerprint: []byte("0123456789abcdef"), RuleID: "github-pat", Description: "GitHub token.",
			Severity: rules.SeverityHigh, Preview: "ghp_… (40)", Path: "dir/a b|c.env", Line: 3, CommitSHA: "c0ffee00c0ffee00"},
		{Fingerprint: []byte("fedcba9876543210"), RuleID: "generic-api-key",
			Severity: rules.SeverityMedium, Preview: "abcd… (32)", Path: "wiki:Home.md", Line: 0},
		{Fingerprint: []byte("aaaaaaaaaaaaaaaa"), RuleID: "github-pat",
			Severity: rules.SeverityLow, Preview: "ghp_… (40)", Path: "x\x1b[2K.txt", Line: 9},
	}
}

func TestFindingsMarkdown(t *testing.T) {
	st := &scanner.Stats{BlobsListed: 3, Gaps: []scanner.Gap{{Blob: "b1", Path: "dump.sql", Reason: scanner.GapTooLarge, Size: 6 << 20}}, SkippedSize: 1}
	st.Warn(".terces.yaml: invalid YAML at line 2. The scan ignores the file")
	var buf bytes.Buffer
	if err := FindingsMarkdown(&buf, []RepoFindings{{Repo: "acme/api", Findings: testFindings()}}, st, ReportOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"## terces: 3 findings", "| Repository | Severity |", "`dir/a b\\|c.env:3`", "`c0ffee00c0ff`", "### 1 blob not scanned in full", "`dump.sql`", "> Warning:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("output holds a raw escape byte")
	}
	buf.Reset()
	_ = FindingsMarkdown(&buf, nil, nil, ReportOptions{})
	if !strings.HasPrefix(buf.String(), "## terces: no findings") {
		t.Errorf("empty report: %q", buf.String())
	}
}

func TestSARIF(t *testing.T) {
	set, err := rules.LoadFS(fstest.MapFS{"r.yaml": {Data: []byte(`
- id: github-pat
  description: GitHub personal access token
  keywords: [ghp_]
  regex: 'ghp_[a-z]{36}'
  severity: high
- id: generic-api-key
  keywords: [key]
  regex: 'key=([a-z]{20})'
  severity: medium
`)}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := SARIFLog(&buf, testFindings(), set, SARIFOptions{ToolVersion: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				RuleIndex           int               `json:"ruleIndex"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Locations           []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "terces" {
		t.Fatalf("header: %+v", log)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 3 {
		t.Fatalf("got %d rules and %d results", len(run.Tool.Driver.Rules), len(run.Results))
	}
	uris := map[string]int{}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %s points to rule %d", r.RuleID, r.RuleIndex)
		}
		if r.PartialFingerprints != nil {
			t.Error("partial fingerprints without StableFingerprints")
		}
		loc := r.Locations[0].PhysicalLocation
		uris[loc.ArtifactLocation.URI] = loc.Region.StartLine
	}
	for uri, line := range map[string]int{"dir/a%20b%7Cc.env": 3, "./wiki:Home.md": 1, "x%1B%5B2K.txt": 9} {
		if got, ok := uris[uri]; !ok || got != line {
			t.Errorf("uri %s: line %d, found %v, all %v", uri, got, ok, uris)
		}
	}
	if run.Tool.Driver.Rules[1].ID != "github-pat" || run.Tool.Driver.Rules[1].Properties.SecuritySeverity != "8.0" {
		t.Errorf("rules: %+v", run.Tool.Driver.Rules)
	}
	buf.Reset()
	_ = SARIFLog(&buf, testFindings(), set, SARIFOptions{StableFingerprints: true})
	if !strings.Contains(buf.String(), "tercesFingerprint/v1") {
		t.Error("stable fingerprints are missing")
	}
}

func TestFindingsHTML(t *testing.T) {
	fs := testFindings()
	fs[0].Path = `</script><img src=x onerror=alert(1)>.env`
	st := &scanner.Stats{Gaps: []scanner.Gap{{Blob: "b1", Path: "<b>dump.sql", Reason: scanner.GapTooLarge, Size: 9}}, SkippedSize: 1}
	var buf bytes.Buffer
	if err := FindingsHTML(&buf, []RepoFindings{{Repo: "acme/api", Findings: fs}}, st, ReportOptions{Target: "acme/<api>"}); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	if strings.Contains(page, "<img") || strings.Contains(page, "<b>dump") || strings.Contains(page, "acme/<api>") {
		t.Fatal("the page holds unescaped repository content")
	}
	if strings.Count(page, "</script>") != 2 {
		t.Errorf("the page has %d script end tags, want 2", strings.Count(page, "</script>"))
	}
	start := strings.Index(page, `id="data">`) + len(`id="data">`)
	end := strings.Index(page[start:], "</script>")
	var r HTMLReport
	if err := json.Unmarshal([]byte(page[start:start+end]), &r); err != nil {
		t.Fatalf("data JSON: %v", err)
	}
	if len(r.Rows) != 3 || r.Columns[0].Name != "Repository" || r.Gaps == nil || len(r.Cards) < 6 {
		t.Errorf("report data: %+v", r)
	}
	if !strings.Contains(page, "default-src 'none'") {
		t.Error("the page has no content security policy")
	}
}

func TestSummary(t *testing.T) {
	s := Summarize([]RepoFindings{{Repo: "acme/api", Findings: testFindings()}, {Repo: "acme/web", Findings: testFindings()[:1]}}, nil)
	if s.Findings != 4 || s.Secrets != 3 || s.BySeverity["high"] != 2 || s.ByRule[0].Name != "github-pat" || s.ByRule[0].Count != 3 {
		t.Errorf("summary: %+v", s)
	}
	if len(s.ByRepo) != 2 || s.ByRepo[0].Name != "acme/api" {
		t.Errorf("by repo: %+v", s.ByRepo)
	}
	var buf bytes.Buffer
	_ = SummaryText(&buf, s)
	for _, want := range []string{"Summary: 4 findings, 3 different secrets.", "0 critical, 2 high, 1 medium, 1 low", "generic-api-key  1"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text summary misses %q:\n%s", want, buf.String())
		}
	}
}
