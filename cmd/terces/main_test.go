package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terces/internal/dbtest"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/store"
	"terces/internal/testsecret"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv(envPrefix+"HMAC_KEY", "")
	a := &app{}
	root := newRootCmd(a)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	a.close()
	return out.String() + errOut.String(), err
}

func TestScanPathExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "scan", "path", dir); err != nil {
		t.Fatalf("clean directory: %v", err)
	}
	pat := testsecret.GitHubPAT()
	if err := os.WriteFile(filepath.Join(dir, "token.env"), []byte("TOKEN="+pat+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "scan", "path", dir)
	if !errors.Is(err, errFindings) {
		t.Fatalf("directory with a token: err %v, want errFindings", err)
	}
	if !strings.Contains(out, "github-pat") || strings.Contains(out, pat) {
		t.Errorf("output must name the rule and hide the secret:\n%s", out)
	}
	if _, err := run(t, "scan", "path", filepath.Join(dir, "missing")); err == nil || errors.Is(err, errFindings) {
		t.Errorf("missing directory: err %v, want an error that is not errFindings", err)
	}
}

func TestDatabaseCommandsNeedConfig(t *testing.T) {
	t.Setenv(envPrefix+"DATABASE_URL", "")
	if _, err := run(t, "findings", "list", "--database-url", ""); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Errorf("findings list without database: %v", err)
	}
}

// Every output format hides the secret, and the text output escapes a
// hostile file name, so it cannot hide a row or change the terminal.
func TestOutputFormats(t *testing.T) {
	dir := t.TempDir()
	pat := testsecret.GitHubPAT()
	hostile := "a\x1b]0;owned\a\x1b[2Kb.env"
	if err := os.WriteFile(filepath.Join(dir, hostile), []byte("TOKEN="+pat+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--format", "text"}, {"--format", "json"}, {"--json"}, {"--format", "markdown"},
		{"--format", "html"}, {"--format", "sarif"}, {"--summary"}, {"--summary", "--format", "markdown"},
	} {
		out, err := run(t, append([]string{"scan", "path", dir}, args...)...)
		if !errors.Is(err, errFindings) {
			t.Errorf("%v: err %v, want errFindings", args, err)
		}
		if strings.Contains(out, pat) {
			t.Errorf("%v: the output holds the secret", args)
		}
		if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
			t.Errorf("%v: the output holds a raw control byte", args)
		}
		if !strings.Contains(out, "github-pat") {
			t.Errorf("%v: the output does not name the rule:\n%s", args, out)
		}
	}
	if _, err := run(t, "scan", "path", dir, "--format", "xml"); err == nil || !strings.Contains(err.Error(), "use text, json") {
		t.Errorf("unknown format: %v", err)
	}
	if _, err := run(t, "scan", "path", dir, "--format", "sarif", "--summary"); err == nil {
		t.Error("--summary with sarif: want an error")
	}
	if _, err := run(t, "scan", "org", "acme", "--format", "sarif"); err == nil || !strings.Contains(err.Error(), "scan repo") {
		t.Errorf("scan org with sarif: %v", err)
	}
}

// A list that the limit cuts says so.
func TestFindingsListSaysWhenItIsCut(t *testing.T) {
	db, dsn := dbtest.New(t)
	ctx := context.Background()
	if _, err := db.UpsertRepo(ctx, &store.Repo{ID: 1, Org: "acme", Name: "api", InstallationID: 1}); err != nil {
		t.Fatal(err)
	}
	var fs []scanner.Finding
	for i := 0; i < 3; i++ {
		fs = append(fs, scanner.Finding{Fingerprint: []byte(fmt.Sprintf("fingerprint-%020d", i)), RuleID: "github-pat",
			Severity: rules.SeverityHigh, Preview: "ghp_… (40)", Path: "a.env", Line: i + 1, BlobSHA: "b1"})
	}
	if _, err := db.RecordFindings(ctx, 1, fs); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "findings", "list", "--database-url", dsn, "--limit", "2")
	if err != nil || !strings.Contains(out, "The list shows the first 2 findings") {
		t.Errorf("cut list: %v\n%s", err, out)
	}
	out, err = run(t, "findings", "list", "--database-url", dsn, "--limit", "2", "--json")
	if err != nil || !strings.Contains(out, `"truncated": true`) {
		t.Errorf("cut JSON list: %v\n%s", err, out)
	}
	out, err = run(t, "findings", "list", "--database-url", dsn)
	if err != nil || !strings.Contains(out, "3 findings") {
		t.Errorf("full list: %v\n%s", err, out)
	}
}
