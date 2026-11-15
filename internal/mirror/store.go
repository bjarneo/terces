package mirror

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Store keeps bare mirrors on disk. It keys each mirror on the numeric
// GitHub repository ID, so a rename or a transfer keeps the same mirror.
//
// Layout:
//
//	<root>/<repo-id>/repo.git
//	<root>/<repo-id>/wiki.git
type Store struct {
	Root string
	// BaseURL is the git host, for example https://github.com.
	BaseURL string
}

// RepoPath returns the path of the repository mirror.
func (s *Store) RepoPath(id int64) string {
	return filepath.Join(s.Root, strconv.FormatInt(id, 10), "repo.git")
}

// WikiPath returns the path of the wiki mirror.
func (s *Store) WikiPath(id int64) string {
	return filepath.Join(s.Root, strconv.FormatInt(id, 10), "wiki.git")
}

// Git returns a Git for a mirror path.
func (s *Store) Git(path string) *Git {
	return &Git{Dir: path, Bare: true}
}

// Exists reports whether a mirror exists at path.
func (s *Store) Exists(path string) bool {
	_, err := os.Stat(filepath.Join(path, "HEAD"))
	return err == nil
}

// FetchOptions selects what Fetch gets.
type FetchOptions struct {
	FullName      string
	Token         string
	DefaultBranch string
	Wiki          bool
}

// Fetch creates or updates the mirror of a repository at path.
//
// Branches and tags are fetched with --prune. GitHub's refs/pull/*/head
// refs are fetched without --prune: a closed or force-pushed pull request
// can still be reachable on GitHub by SHA, so the mirror keeps it.
func (s *Store) Fetch(ctx context.Context, path string, opts FetchOptions) error {
	url := strings.TrimSuffix(s.BaseURL, "/") + "/" + opts.FullName
	if opts.Wiki {
		url += ".wiki.git"
	} else {
		url += ".git"
	}
	env := AuthEnv(s.BaseURL, opts.Token)

	if !s.Exists(path) {
		// Fetch into a temporary directory first. An interrupted first
		// fetch then leaves no half-filled mirror behind.
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		tmp, err := os.MkdirTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		g := &Git{Dir: tmp, Bare: true, Env: env}
		if _, err := g.Run(ctx, "init", "--bare", "--quiet"); err != nil {
			return err
		}
		// The mirror never gets commits of its own. Keep reflogs off to
		// save space.
		if _, err := g.Run(ctx, "config", "core.logAllRefUpdates", "false"); err != nil {
			return err
		}
		if err := s.fetch(ctx, g, url, opts); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	return s.fetch(ctx, &Git{Dir: path, Bare: true, Env: env}, url, opts)
}

// lowSpeed makes git stop a transfer that stays below 1 KB/s for 5
// minutes. The fetch time limit of the caller covers the rest.
var lowSpeed = []string{"-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=300"}

func (s *Store) fetch(ctx context.Context, g *Git, url string, opts FetchOptions) error {
	args := append(append([]string{}, lowSpeed...), "fetch", "--quiet", "--prune", "--no-tags", "--force", url,
		"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
	if _, err := g.Run(ctx, args...); err != nil {
		return err
	}
	if !opts.Wiki {
		args := append(append([]string{}, lowSpeed...), "fetch", "--quiet", "--no-tags", "--force", url,
			"+refs/pull/*/head:refs/pull/*/head")
		if _, err := g.Run(ctx, args...); err != nil {
			return err
		}
	}
	// Point HEAD at the default branch. The scanner reads
	// .terces.yaml and CODEOWNERS from HEAD.
	for _, branch := range []string{opts.DefaultBranch, "main", "master"} {
		if branch == "" {
			continue
		}
		if _, err := g.Run(ctx, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch); err != nil {
			continue
		}
		_, err := g.Run(ctx, "symbolic-ref", "HEAD", "refs/heads/"+branch)
		return err
	}
	return nil
}

// Remove deletes a mirror from disk.
func (s *Store) Remove(path string) error {
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(s.Root)+string(filepath.Separator)) {
		return fmt.Errorf("refuse to remove %s: it is outside %s", path, s.Root)
	}
	return os.RemoveAll(path)
}
