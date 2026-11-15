package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terces/internal/gittest"
	"terces/internal/mirror"
	"terces/internal/repoconfig"
	"terces/internal/scanner"
	"terces/internal/testsecret"
)

// A tip of an earlier scan can be gone: the branch was deleted, the fetch
// pruned it and gc dropped the commit. The next incremental scan must not
// fail on it.
func TestScanWithPrunedTip(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	repo.Write("README.md", "# demo\n")
	repo.Commit("init")
	repo.Git("checkout", "-q", "-b", "stale")
	repo.Write("notes.txt", "draft\n")
	stale := repo.Commit("stale work")
	repo.Git("checkout", "-q", "main")
	repo.Git("branch", "-D", "stale")
	repo.Git("reflog", "expire", "--expire=now", "--all")
	repo.Git("gc", "-q", "--prune=now")
	if out, err := (&mirror.Git{Dir: repo.Dir}).Run(ctx, "cat-file", "-e", stale); err == nil {
		t.Fatalf("the stale commit still exists: %s", out)
	}

	pat := testsecret.GitHubPAT()
	repo.Write("app.env", "GITHUB_TOKEN="+pat+"\n")
	repo.Commit("add token")
	fs, _, err := newScanner(t).ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{Exclude: []string{stale}})
	if err != nil {
		t.Fatalf("scan with a pruned tip: %v", err)
	}
	if summary(fs) != "github-pat@app.env" {
		t.Errorf("findings: %s", summary(fs))
	}
}

// An author name with a control byte must not move the attribution to the
// commit before it.
func TestAttributionWithControlByteInAuthor(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	repo.Write("README.md", "# demo\n")
	repo.Commit("alice commit")
	t.Setenv("GIT_AUTHOR_NAME", "mallory\x02x\x02y")
	t.Setenv("GIT_AUTHOR_EMAIL", "mallory@example.com")
	repo.Write("app.env", "GITHUB_TOKEN="+testsecret.GitHubPAT()+"\n")
	mallory := repo.Commit("mallory commit")

	fs, _, err := newScanner(t).ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].CommitSHA != mallory || fs[0].AuthorEmail != "mallory@example.com" {
		t.Fatalf("attribution: %+v, want commit %s", fs, mallory)
	}
}

// git rev-list prints a path with a newline as two lines. The finding must
// get the real path only.
func TestNewlineInPath(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	name := "dir\nx.env"
	repo.Write(name, "GITHUB_TOKEN="+testsecret.GitHubPAT()+"\n")
	repo.Commit("odd name")
	fs, _, err := newScanner(t).ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Path != name {
		t.Fatalf("findings: %q", summary(fs))
	}
}

// A blob above the size limit and a blob at the match limit are gaps. The
// scan reports them on each run, also when the cache has the blob.
func TestGapsAreReportedOnEachScan(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	repo.Write("dump.sql", "-- "+strings.Repeat("x", 600)+"\nGITHUB_TOKEN="+testsecret.GitHubPAT()+"\n")
	var b strings.Builder
	for i := 0; i < 210; i++ {
		b.WriteString("GITHUB_TOKEN=" + testsecret.GitHubPAT() + "\n")
	}
	repo.Write("tokens.log", b.String())
	// A large binary blob is not a gap.
	repo.Write("firmware.dat", "\x00\x01"+strings.Repeat("\xff", 900))
	repo.Commit("gaps")

	// First, both blobs fit the size limit, and tokens.log has more
	// different secrets than the match limit.
	sc := newScanner(t)
	sc.MaxBlobSize = 16 << 10
	cache := &memCache{}
	for run := 0; run < 2; run++ {
		_, st, err := sc.ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{Cache: cache})
		if err != nil {
			t.Fatal(err)
		}
		if st.Capped != 1 || st.SkippedSize != 0 {
			t.Errorf("run %d: capped %d, too large %d, want 1 and 0", run, st.Capped, st.SkippedSize)
		}
		if len(st.Gaps) != 1 || st.Gaps[0].Path != "tokens.log" || st.Gaps[0].Reason != scanner.GapMatchLimit {
			t.Errorf("run %d: gaps %+v", run, st.Gaps)
		}
	}

	// Then both blobs are above the size limit.
	sc.MaxBlobSize = 500
	for run := 0; run < 2; run++ {
		_, st, err := sc.ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{Cache: cache})
		if err != nil {
			t.Fatal(err)
		}
		paths := map[string]string{}
		for _, g := range st.Gaps {
			paths[g.Path] = g.Reason
		}
		if paths["dump.sql"] != scanner.GapTooLarge || paths["tokens.log"] != scanner.GapTooLarge || st.SkippedSize != 2 {
			t.Errorf("run %d: gaps %+v, too large %d", run, st.Gaps, st.SkippedSize)
		}
		if _, ok := paths["firmware.dat"]; ok || st.SkippedBinary != 1 {
			t.Errorf("run %d: a binary blob is a gap, or binary count %d is not 1", run, st.SkippedBinary)
		}
	}
}

// scan path must not follow a linked .terces.yaml, and an invalid file
// must not stop the scan or show its content.
func TestDirConfigIsReadSafely(t *testing.T) {
	ctx := context.Background()
	sc := newScanner(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.env"), []byte("GITHUB_TOKEN="+testsecret.GitHubPAT()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, filepath.Join(dir, repoconfig.FileName)); err != nil {
		t.Fatal(err)
	}
	fs, st, err := sc.ScanDir(ctx, dir)
	if err != nil {
		t.Fatalf("scan with a linked config: %v", err)
	}
	if len(fs) != 1 || len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], "not a regular file") {
		t.Errorf("findings %d, warnings %q", len(fs), st.Warnings)
	}

	dir = t.TempDir()
	key := "KEYMATERIAL" + testsecret.Rand("A-Z", 20)
	if err := os.WriteFile(filepath.Join(dir, repoconfig.FileName), []byte("ignore: "+key+"\n  - [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, st, err = sc.ScanDir(ctx, dir)
	if err != nil {
		t.Fatalf("scan with an invalid config: %v", err)
	}
	if len(st.Warnings) != 1 || strings.Contains(st.Warnings[0], "KEYMAT") {
		t.Errorf("warnings %q must name the problem without the content", st.Warnings)
	}
}
