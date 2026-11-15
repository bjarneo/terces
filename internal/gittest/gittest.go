// Package gittest creates temporary git repositories for tests.
package gittest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Repo is a temporary repository with a working tree.
type Repo struct {
	t   testing.TB
	Dir string
}

// Isolate keeps the git config of the user out of the test. It sets the
// environment for the test and for all git processes that the test starts.
func Isolate(t testing.TB) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "Test Author")
	t.Setenv("GIT_AUTHOR_EMAIL", "author@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "Test Author")
	t.Setenv("GIT_COMMITTER_EMAIL", "author@example.com")
}

// New creates an empty repository with the branch "main".
func New(t testing.TB) *Repo {
	t.Helper()
	Isolate(t)
	r := &Repo{t: t, Dir: t.TempDir()}
	r.Git("init", "-q", "-b", "main")
	r.Git("config", "commit.gpgsign", "false")
	return r
}

// Git runs git in the repository and returns the trimmed stdout.
func (r *Repo) Git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.Dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// Write writes a file in the working tree.
func (r *Repo) Write(path, content string) {
	r.t.Helper()
	full := filepath.Join(r.Dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// Remove deletes a file from the working tree.
func (r *Repo) Remove(path string) {
	r.t.Helper()
	if err := os.Remove(filepath.Join(r.Dir, path)); err != nil {
		r.t.Fatal(err)
	}
}

// Commit stages all changes, commits them and returns the commit ID.
func (r *Repo) Commit(msg string) string {
	r.t.Helper()
	r.Git("add", "-A")
	r.Git("commit", "-q", "--allow-empty", "-m", msg)
	return r.Git("rev-parse", "HEAD")
}
