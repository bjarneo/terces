package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"terces/internal/engine"
	"terces/internal/fingerprint"
	"terces/internal/gittest"
	"terces/internal/mirror"
	"terces/internal/repoconfig"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/testsecret"
	rulesdata "terces/rules"
)

func newScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	set, err := rules.LoadFS(rulesdata.FS, "built-in")
	if err != nil {
		t.Fatal(err)
	}
	h, err := fingerprint.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return &scanner.Scanner{Engine: engine.New(set), Hasher: h, MaxBlobSize: scanner.DefaultMaxBlobSize, Workers: 2}
}

type memCache struct {
	mu sync.Mutex
	m  map[string]scanner.BlobResult
	v  int64
}

func (c *memCache) Lookup(_ context.Context, version int64, shas []string) (map[string]scanner.BlobResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]scanner.BlobResult{}
	if version != c.v {
		return out, nil
	}
	for _, s := range shas {
		if bf, ok := c.m[s]; ok {
			out[s] = bf
		}
	}
	return out, nil
}

func (c *memCache) Save(_ context.Context, version int64, res map[string]scanner.BlobResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || c.v != version {
		c.m, c.v = map[string]scanner.BlobResult{}, version
	}
	for k, v := range res {
		c.m[k] = v
	}
	return nil
}

func summary(fs []scanner.Finding) string {
	var parts []string
	for _, f := range fs {
		parts = append(parts, f.RuleID+"@"+f.Path)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func TestScanHistory(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)

	keyID, secret, pat := testsecret.AWSKeyID(), testsecret.AWSSecret(), testsecret.GitHubPAT()
	repo.Write("README.md", "# demo\n")
	repo.Write("config/aws.env", "aws_access_key_id = "+keyID+"\naws_secret_access_key = "+secret+"\n")
	first := repo.Commit("add config")
	repo.Remove("config/aws.env")
	repo.Commit("remove config")
	repo.Write("vendor/lib/token.txt", "token: "+pat+"\n")
	repo.Write("docs/setup.md", "Use GITHUB_TOKEN="+pat+"\n")
	repo.Commit("add docs")

	g := &mirror.Git{Dir: repo.Dir}
	cache := &memCache{}
	fs, st, err := sc.ScanHistory(ctx, g, scanner.HistoryOptions{Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	want := "aws-access-key-id@config/aws.env aws-secret-access-key@config/aws.env github-pat@docs/setup.md"
	if got := summary(fs); got != want {
		t.Fatalf("findings:\n got %s\nwant %s", got, want)
	}
	if st.SkippedPath != 1 {
		t.Errorf("skipped paths = %d, want 1 for vendor/", st.SkippedPath)
	}
	for _, f := range fs {
		if f.Path == "config/aws.env" && (f.CommitSHA != first || f.AuthorEmail != "author@example.com") {
			t.Errorf("attribution of %s: commit %s author %s, want %s", f.RuleID, f.CommitSHA, f.AuthorEmail, first)
		}
		if strings.Contains(f.Preview, secret) || strings.Contains(f.Preview, pat) {
			t.Errorf("preview %q contains the secret", f.Preview)
		}
	}

	// A second full scan reads every blob from the cache.
	fs2, st2, err := sc.ScanHistory(ctx, g, scanner.HistoryOptions{Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	if summary(fs2) != want || st2.BlobsScanned != 0 || st2.BlobsCached == 0 {
		t.Errorf("cached scan: findings %s, scanned %d, cached %d", summary(fs2), st2.BlobsScanned, st2.BlobsCached)
	}

	// An incremental scan sees only the new commit.
	tips, err := g.Tips(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.Write("deploy/key.pem", testsecret.PrivateKey())
	repo.Commit("add key")
	var exclude []string
	for _, v := range tips {
		exclude = append(exclude, v)
	}
	fs3, _, err := sc.ScanHistory(ctx, g, scanner.HistoryOptions{Exclude: exclude})
	if err != nil {
		t.Fatal(err)
	}
	if got := summary(fs3); got != "generic-private-key@deploy/key.pem" {
		t.Errorf("incremental scan: got %s", got)
	}
}

func TestRepoConfigIgnoresFingerprint(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)
	pat := testsecret.GitHubPAT()
	repo.Write("a.txt", "token "+pat+"\n")
	repo.Commit("one")
	fp := fingerprint.Hex(sc.Hasher.Fingerprint([]byte(pat)))
	repo.Write(".terces.yaml", "ignore:\n  - fingerprint: "+fp[:20]+"\n    note: test value\n")
	repo.Commit("ignore")

	fs, _, err := sc.ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{
		Config: mustConfig(t, ctx, repo.Dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("got %s, want no findings", summary(fs))
	}
}

func mustConfig(t *testing.T, ctx context.Context, dir string) *repoconfig.Config {
	t.Helper()
	cfg, err := scanner.LoadConfig(ctx, &mirror.Git{Dir: dir}, "HEAD")
	if err != nil || cfg == nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

func TestScanStaged(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)
	g := &mirror.Git{Dir: repo.Dir}
	oldPAT, newPAT := testsecret.GitHubPAT(), testsecret.GitHubPAT()

	// Initial commit: nothing is committed yet, so all staged files are new.
	repo.Write("app.env", "TOKEN="+oldPAT+"\n")
	repo.Git("add", "app.env")
	fs, _, err := sc.ScanStaged(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if summary(fs) != "github-pat@app.env" {
		t.Fatalf("initial staged scan: got %s", summary(fs))
	}
	repo.Commit("initial")

	// An edit that keeps the old token is clean.
	repo.Write("app.env", "TOKEN="+oldPAT+"\nDEBUG=1\n")
	repo.Git("add", "app.env")
	if fs, _, err = sc.ScanStaged(ctx, g); err != nil || len(fs) != 0 {
		t.Fatalf("edit with old token: got %s, err %v", summary(fs), err)
	}
	// Moving the old token to another file is clean.
	repo.Git("mv", "app.env", "prod.env")
	if fs, _, err = sc.ScanStaged(ctx, g); err != nil || len(fs) != 0 {
		t.Fatalf("moved token: got %s, err %v", summary(fs), err)
	}
	// A new token is a finding. Unstaged changes are not scanned.
	repo.Write("prod.env", "TOKEN="+oldPAT+"\nNEW="+newPAT+"\n")
	repo.Git("add", "prod.env")
	repo.Write("unstaged.txt", "x="+testsecret.GitHubPAT()+"\n")
	fs, _, err = sc.ScanStaged(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Path != "prod.env" || fs[0].Line != 2 {
		t.Fatalf("new token: got %+v", fs)
	}
}

func TestScanRange(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)
	g := &mirror.Git{Dir: repo.Dir}
	oldPAT, tempPAT := testsecret.GitHubPAT(), testsecret.GitHubPAT()

	repo.Write("app.env", "TOKEN="+oldPAT+"\n")
	base := repo.Commit("base")
	repo.Git("checkout", "-q", "-b", "feature")
	repo.Write("app.env", "TOKEN="+oldPAT+"\nDEBUG=1\n")
	repo.Write("tmp.txt", "oops "+tempPAT+"\n")
	repo.Commit("add temp token")
	repo.Remove("tmp.txt")
	head := repo.Commit("remove temp token")

	fs, _, err := sc.ScanRange(ctx, g, base, head, scanner.RangeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Path != "tmp.txt" {
		t.Fatalf("got %s, want the intermediate token only", summary(fs))
	}
	if fs[0].CommitSHA == "" || fs[0].CommitSHA == base {
		t.Errorf("attribution: got commit %q", fs[0].CommitSHA)
	}
	if _, _, err := sc.ScanRange(ctx, g, "nope", head, scanner.RangeOptions{}); err == nil {
		t.Error("unknown base: want an error")
	}
}

func TestScanDir(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sc := newScanner(t)
	write := func(p, s string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("src/settings.py", "GITHUB_TOKEN = '"+testsecret.GitHubPAT()+"'\n")
	write("node_modules/pkg/index.js", "t='"+testsecret.GitHubPAT()+"'\n")
	write("bin/blob.dat", "\x00\x01"+testsecret.GitHubPAT())
	write("test/fixtures/key.pem", testsecret.PrivateKey())

	fs, st, err := sc.ScanDir(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := summary(fs); got != "generic-private-key@test/fixtures/key.pem github-pat@src/settings.py" {
		t.Fatalf("got %s", got)
	}
	for _, f := range fs {
		if f.Path == "test/fixtures/key.pem" && f.Severity != rules.SeverityLow {
			t.Errorf("fixture severity = %v, want low", f.Severity)
		}
	}
	if st.SkippedBinary != 1 {
		t.Errorf("skipped binary = %d, want 1", st.SkippedBinary)
	}
}

func TestSkippedPathDoesNotHideACopy(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)
	g := &mirror.Git{Dir: repo.Dir}
	repo.Write("README.md", "# demo\n")
	base := repo.Commit("base")

	// The same blob at a skipped path and at a normal path. rev-list
	// reports the blob at node_modules/ only, because it sorts first.
	content := "token: " + testsecret.GitHubPAT() + "\n"
	repo.Write("node_modules/pkg/config.txt", content)
	repo.Write("src/config.txt", content)
	head := repo.Commit("add both")

	fs, _, err := sc.ScanRange(ctx, g, base, head, scanner.RangeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if summary(fs) != "github-pat@src/config.txt" {
		t.Fatalf("range: got %q, want the src/ copy", summary(fs))
	}

	// Incremental: the blob first lands in vendor/, and a later commit
	// copies it to app/. The incremental scan must report the copy.
	repo2 := gittest.New(t)
	g2 := &mirror.Git{Dir: repo2.Dir}
	other := "key: " + testsecret.GitHubPAT() + "\n"
	repo2.Write("vendor/x/cfg.txt", other)
	repo2.Commit("vendor")
	tips, _ := g2.Tips(ctx)
	var exclude []string
	for _, v := range tips {
		exclude = append(exclude, v)
	}
	if fs, _, err := sc.ScanHistory(ctx, g2, scanner.HistoryOptions{}); err != nil || len(fs) != 0 {
		t.Fatalf("vendor only: got %q, err %v", summary(fs), err)
	}
	repo2.Write("app/cfg.txt", other)
	repo2.Commit("copy")
	fs, _, err = sc.ScanHistory(ctx, g2, scanner.HistoryOptions{Exclude: exclude})
	if err != nil {
		t.Fatal(err)
	}
	if summary(fs) != "github-pat@app/cfg.txt" || fs[0].CommitSHA == "" {
		t.Fatalf("incremental copy: got %+v", fs)
	}
}

func TestAllPathsOfABlobGetALocation(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)
	content := "token: " + testsecret.GitHubPAT() + "\n"
	repo.Write("a/one.txt", content)
	repo.Write("b/two.txt", content)
	repo.Commit("two copies")
	fs, _, err := sc.ScanHistory(ctx, &mirror.Git{Dir: repo.Dir}, scanner.HistoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if summary(fs) != "github-pat@a/one.txt github-pat@b/two.txt" {
		t.Fatalf("got %q", summary(fs))
	}
}

func TestRangeReadsAllowlistFromBase(t *testing.T) {
	ctx := context.Background()
	repo := gittest.New(t)
	sc := newScanner(t)
	g := &mirror.Git{Dir: repo.Dir}
	repo.Write("README.md", "# demo\n")
	base := repo.Commit("base")
	pat := testsecret.GitHubPAT()
	fp := fingerprint.Hex(sc.Hasher.Fingerprint([]byte(pat)))
	// The change adds a secret and an ignore entry for it.
	repo.Write("app.env", "TOKEN="+pat+"\n")
	repo.Write(".terces.yaml", "ignore:\n  - "+fp+"\n")
	head := repo.Commit("add token and ignore it")
	fs, _, err := sc.ScanRange(ctx, g, base, head, scanner.RangeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %q: an ignore entry in the change must not apply to the change", summary(fs))
	}
}

func TestVersionDependsOnKey(t *testing.T) {
	a := newScanner(t)
	b := newScanner(t)
	b.Hasher, _ = fingerprint.New([]byte(strings.Repeat("z", 32)))
	if a.Version() == b.Version() {
		t.Error("scanners with different keys must use different cache versions")
	}
}
