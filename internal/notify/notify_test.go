package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"terces/internal/rules"
	"terces/internal/scanner"
)

func TestCodeowners(t *testing.T) {
	c := ParseCodeowners([]byte(`
# comment
*           @acme/everyone
*.tf        @acme/infra
/deploy/    @acme/sre @alice
docs/       @acme/docs # trailing comment
/vendor/
`))
	cases := map[string]string{
		"main.go":            "@acme/everyone",
		"infra/main.tf":      "@acme/infra",
		"deploy/key.pem":     "@acme/sre @alice",
		"web/docs/readme.md": "@acme/docs",
		"vendor/x.go":        "",
	}
	for path, want := range cases {
		if got := strings.Join(c.Owners(path), " "); got != want {
			t.Errorf("Owners(%q) = %q, want %q", path, got, want)
		}
	}
	var nilC *Codeowners
	if nilC.Owners("a") != nil {
		t.Error("nil Codeowners must return no owners")
	}
}

func TestSlackNewFindings(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg struct{ Text string }
		_ = json.Unmarshal(body, &msg)
		got = append(got, msg.Text)
	}))
	defer srv.Close()

	s := NewSlack(srv.URL, "https://github.com")
	fs := []scanner.Finding{
		{Fingerprint: []byte("0123456789abcdef"), RuleID: "github-pat", Severity: rules.SeverityHigh, Preview: "ghp_… (40)",
			Path: "deploy/app.env", Line: 2, CommitSHA: "c0ffee", AuthorEmail: "dev@example.com"},
		{Fingerprint: []byte("fedcba9876543210"), RuleID: "generic-api-key", Severity: rules.SeverityMedium, Preview: "abcd… (32)", Path: "x"},
	}
	owners := ParseCodeowners([]byte("/deploy/ @acme/sre\n"))
	if err := s.NewFindings(context.Background(), RepoRef{"acme", "api"}, fs, owners); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d messages, want 1", len(got))
	}
	msg := got[0]
	for _, want := range []string{"1 new secret in acme/api", "github-pat", "https://github.com/acme/api/commit/c0ffee", "owners @acme/sre", "ghp_… (40)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message misses %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "generic-api-key") {
		t.Error("the message lists a medium finding")
	}

	got = nil
	if err := s.NewFindings(context.Background(), RepoRef{"acme", "api"}, fs[1:], nil); err != nil || len(got) != 0 {
		t.Errorf("medium only: %d messages, err %v", len(got), err)
	}
}

func TestSlackErrorHidesURL(t *testing.T) {
	url := "https://hooks.example.com/services/T000/B000/secretpart\r"
	s := NewSlack(url, "")
	err := s.post(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), "secretpart") {
		t.Fatalf("error %v must not contain the URL", err)
	}
}
