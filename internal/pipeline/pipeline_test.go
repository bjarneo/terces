package pipeline_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"terces/internal/dbtest"
	"terces/internal/engine"
	"terces/internal/fingerprint"
	"terces/internal/githubapp"
	"terces/internal/gittest"
	"terces/internal/mirror"
	"terces/internal/pipeline"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/store"
	"terces/internal/testsecret"
	rulesdata "terces/rules"
)

// fakeGitHub serves the installation and repository endpoints. An
// installation listed in failing answers 403 to its repository list.
type fakeGitHub struct {
	mu      sync.Mutex
	insts   map[int64]string
	repos   map[int64][]githubapp.Repository
	failing map[int64]bool
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/app/installations":
		var list []map[string]any
		for id, login := range f.insts {
			list = append(list, map[string]any{"id": id, "account": map[string]any{"login": login, "type": "Organization"}})
		}
		_ = json.NewEncoder(w).Encode(list)
	case strings.HasSuffix(r.URL.Path, "/access_tokens"):
		var id int64
		fmt.Sscanf(r.URL.Path, "/app/installations/%d/access_tokens", &id)
		fmt.Fprintf(w, `{"token":"tok-%d","expires_at":%q}`, id, time.Now().Add(time.Hour).Format(time.RFC3339))
	case r.URL.Path == "/installation/repositories":
		var id int64
		fmt.Sscanf(r.Header.Get("Authorization"), "token tok-%d", &id)
		if f.failing[id] {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"this org has an IP allow list"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(f.repos[id]), "repositories": f.repos[id]})
	default:
		http.NotFound(w, r)
	}
}

type env struct {
	gh      *fakeGitHub
	app     *githubapp.App
	db      *store.Store
	remotes string
	mirrors string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, _ := dbtest.New(t)
	gittest.Isolate(t)
	gh := &fakeGitHub{insts: map[int64]string{}, repos: map[int64][]githubapp.Repository{}, failing: map[int64]bool{}}
	srv := httptest.NewServer(gh)
	t.Cleanup(srv.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app, err := githubapp.New("1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &env{gh: gh, app: app, db: db, remotes: t.TempDir(), mirrors: t.TempDir()}
}

// remote creates a bare repository at <remotes>/<fullName>.git with one
// commit that holds a token.
func (e *env) remote(t *testing.T, fullName string) {
	t.Helper()
	work := gittest.New(t)
	work.Write("app.env", "GITHUB_TOKEN="+testsecret.GitHubPAT()+"\n")
	work.Commit("init")
	work.Git("clone", "-q", "--bare", work.Dir, filepath.Join(e.remotes, fullName+".git"))
}

func (e *env) pipeline(t *testing.T, key string) *pipeline.Pipeline {
	t.Helper()
	set, err := rules.LoadFS(rulesdata.FS, "built-in")
	if err != nil {
		t.Fatal(err)
	}
	h, err := fingerprint.New([]byte(strings.Repeat(key, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return &pipeline.Pipeline{
		Store:   e.db,
		GitHub:  e.app,
		Mirrors: &mirror.Store{Root: e.mirrors, BaseURL: e.remotes},
		Scanner: &scanner.Scanner{Engine: engine.New(set), Hasher: h, MaxBlobSize: scanner.DefaultMaxBlobSize, Workers: 2},
	}
}

// One installation with a failing repository list must not stop the sync
// of the other installations.
func TestSyncContinuesAfterAnInstallationFails(t *testing.T) {
	e := newEnv(t)
	e.gh.insts[1], e.gh.insts[2] = "org-a", "org-b"
	e.gh.failing[1] = true
	e.gh.repos[2] = []githubapp.Repository{{ID: 20, Name: "api", FullName: "org-b/api", DefaultBranch: "main"}}
	e.remote(t, "org-b/api")

	sum, err := e.pipeline(t, "k").Sync(context.Background(), pipeline.SyncOptions{Scan: true})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if sum.Installations != 2 || sum.InstallErrors != 1 || sum.Fetched != 1 || sum.Scanned != 1 || sum.NewSecrets != 1 {
		t.Errorf("summary: %+v", sum)
	}

	// When all installations fail, Sync returns an error.
	e.gh.failing[2] = true
	if _, err := e.pipeline(t, "k").Sync(context.Background(), pipeline.SyncOptions{}); err == nil {
		t.Error("sync with all installations failing: want an error")
	}
}

// An archived repository gets no new fetch, but a new rules version still
// scans its mirror again.
func TestArchivedRepositoryGetsANewScan(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.gh.insts[1] = "acme"
	e.gh.repos[1] = []githubapp.Repository{{ID: 10, Name: "old", FullName: "acme/old", DefaultBranch: "main"}}
	e.remote(t, "acme/old")
	if _, err := e.pipeline(t, "k").Sync(ctx, pipeline.SyncOptions{Scan: true}); err != nil {
		t.Fatal(err)
	}
	e.gh.repos[1][0].Archived = true
	// The sync that sees the archive gets one last fetch.
	if sum, err := e.pipeline(t, "k").Sync(ctx, pipeline.SyncOptions{Scan: true}); err != nil || sum.Fetched != 1 {
		t.Fatalf("archive sync: %+v %v", sum, err)
	}
	// A new HMAC key changes the scanner version.
	p := e.pipeline(t, "j")
	sum, err := p.Sync(ctx, pipeline.SyncOptions{Scan: true})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Fetched != 0 || sum.Scanned != 1 || sum.NewSecrets != 1 {
		t.Errorf("summary after the version change: %+v", sum)
	}
	r, err := e.db.GetRepo(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tips == nil || r.Tips.Version != p.Scanner.Version() {
		t.Errorf("tips version: %+v, want %d", r.Tips, p.Scanner.Version())
	}
}

// A fetch from a server that accepts the connection and then sends
// nothing must fail at the fetch time limit.
func TestFetchTimeout(t *testing.T) {
	e := newEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	p := e.pipeline(t, "k")
	p.Mirrors.BaseURL = "http://" + ln.Addr().String()
	p.FetchTimeout = time.Second
	r := &store.Repo{ID: 30, Org: "acme", Name: "slow", InstallationID: 1}
	start := time.Now()
	err = p.FetchRepo(context.Background(), r)
	if err == nil || !strings.Contains(err.Error(), "took longer than") {
		t.Fatalf("fetch: %v, want a time limit error", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("fetch stopped after %s", d)
	}
}
