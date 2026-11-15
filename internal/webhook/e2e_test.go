package webhook_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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
	"terces/internal/notify"
	"terces/internal/pipeline"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/store"
	"terces/internal/testsecret"
	"terces/internal/webhook"
	rulesdata "terces/rules"
)

const installationToken = "ghs_" + "testinstallationtoken000000000000000"

// fakeGitHub serves the API endpoints that terces calls and records
// the check runs.
type fakeGitHub struct {
	t     *testing.T
	mu    sync.Mutex
	runs  map[int64][]githubapp.CheckRun
	runID int64
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(r.URL.Path, "/app/") && !strings.HasPrefix(auth, "Bearer ") {
		f.t.Errorf("%s: app endpoint without JWT", r.URL.Path)
	}
	switch {
	case r.URL.Path == "/app/installations":
		fmt.Fprint(w, `[{"id":10,"account":{"login":"acme","type":"Organization"}}]`)
	case r.URL.Path == "/app/installations/10/access_tokens":
		fmt.Fprintf(w, `{"token":%q,"expires_at":%q}`, installationToken, time.Now().Add(time.Hour).Format(time.RFC3339))
	case r.URL.Path == "/installation/repositories":
		if auth != "token "+installationToken {
			f.t.Errorf("repositories: auth %q", auth)
		}
		fmt.Fprint(w, `{"repositories":[{"id":101,"name":"api","full_name":"acme/api","owner":{"login":"acme"},
			"private":true,"default_branch":"main","has_wiki":false}]}`)
	case r.URL.Path == "/repos/acme/api/check-runs" && r.Method == http.MethodPost:
		var run githubapp.CheckRun
		_ = json.NewDecoder(r.Body).Decode(&run)
		f.runID++
		f.runs[f.runID] = []githubapp.CheckRun{run}
		fmt.Fprintf(w, `{"id":%d}`, f.runID)
	case strings.HasPrefix(r.URL.Path, "/repos/acme/api/check-runs/") && r.Method == http.MethodPatch:
		var id int64
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/repos/acme/api/check-runs/"), "%d", &id)
		var run githubapp.CheckRun
		_ = json.NewDecoder(r.Body).Decode(&run)
		f.runs[id] = append(f.runs[id], run)
		fmt.Fprint(w, `{}`)
	default:
		f.t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) last() []githubapp.CheckRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[f.runID]
}

type slackSink struct {
	mu   sync.Mutex
	msgs []string
	down bool
}

func (s *slackSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m struct{ Text string }
	_ = json.Unmarshal(body, &m)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.msgs = append(s.msgs, m.Text)
}

func TestEndToEnd(t *testing.T) {
	db, _ := dbtest.New(t)
	ctx := context.Background()

	// The "GitHub" remote is a bare repository on disk.
	remoteRoot := t.TempDir()
	work := gittest.New(t)
	keyID, awsSecret := testsecret.AWSKeyID(), testsecret.AWSSecret()
	work.Write("README.md", "# api\n")
	work.Write("deploy/prod.env", "aws_access_key_id="+keyID+"\naws_secret_access_key="+awsSecret+"\n")
	work.Write("CODEOWNERS", "/deploy/ @acme/sre\n")
	work.Commit("initial")
	work.Remove("deploy/prod.env")
	base := work.Commit("remove env file")
	bare := filepath.Join(remoteRoot, "acme", "api.git")
	work.Git("clone", "-q", "--bare", work.Dir, bare)

	gh := &fakeGitHub{t: t, runs: map[int64][]githubapp.CheckRun{}}
	api := httptest.NewServer(gh)
	defer api.Close()
	sink := &slackSink{}
	slackSrv := httptest.NewServer(sink)
	defer slackSrv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	app, err := githubapp.New("1", keyPEM, api.URL)
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.LoadFS(rulesdata.FS, "built-in")
	if err != nil {
		t.Fatal(err)
	}
	hasher, _ := fingerprint.New(bytes.Repeat([]byte{7}, 32))
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sw := &pipeline.Pipeline{
		Store:   db,
		GitHub:  app,
		Mirrors: &mirror.Store{Root: filepath.Join(t.TempDir(), "mirrors"), BaseURL: "file://" + remoteRoot},
		Scanner: &scanner.Scanner{Engine: engine.New(set), Hasher: hasher, MaxBlobSize: scanner.DefaultMaxBlobSize, Workers: 2},
		Slack:   notify.NewSlack(slackSrv.URL, "https://github.com"),
		Log:     log,
	}

	// 1. Sync and scan find the AWS keys in history.
	sum, err := sw.Sync(ctx, pipeline.SyncOptions{Scan: true})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Repos != 1 || sum.Fetched != 1 || sum.Scanned != 1 || sum.NewSecrets != 2 {
		t.Fatalf("sync summary: %+v", sum)
	}
	if len(sink.msgs) != 1 || !strings.Contains(sink.msgs[0], "2 new secrets in acme/api") || !strings.Contains(sink.msgs[0], "owners @acme/sre") {
		t.Fatalf("slack messages: %q", sink.msgs)
	}

	// A second sync with scan finds nothing new and sends no alert.
	if sum, err = sw.Sync(ctx, pipeline.SyncOptions{Scan: true}); err != nil || sum.NewSecrets != 0 {
		t.Fatalf("second sync: %+v %v", sum, err)
	}
	if len(sink.msgs) != 1 {
		t.Errorf("second sync sent %d more alerts", len(sink.msgs)-1)
	}

	// 2. A pull request with a new token fails the check.
	worker := &webhook.Worker{Store: db, Pipeline: sw, Log: log}
	handler := &webhook.Handler{Secret: []byte("hook-secret"), Queue: db, Log: log}
	pat := testsecret.GitHubPAT()
	work.Git("checkout", "-q", "-b", "feature")
	work.Write("app/config.py", "TOKEN = '"+pat+"'\n")
	head := work.Commit("add config")
	work.Git("push", "-q", bare, "feature:refs/pull/1/head")

	sendPR := func(headSHA string) {
		t.Helper()
		body := fmt.Sprintf(`{"action":"synchronize","installation":{"id":10},
			"repository":{"id":101,"name":"api","full_name":"acme/api","owner":{"login":"acme"},"default_branch":"main"},
			"pull_request":{"number":1,"head":{"sha":%q},"base":{"sha":%q,"ref":"main"}}}`, headSHA, base)
		m := hmac.New(sha256.New, []byte("hook-secret"))
		m.Write([]byte(body))
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("webhook status %d: %s", rec.Code, rec.Body)
		}
		ran, err := worker.RunOne(ctx)
		if err != nil || !ran {
			t.Fatalf("worker: ran %v err %v", ran, err)
		}
	}
	sendPR(head)
	runs := gh.last()
	if len(runs) < 2 || runs[0].Status != "in_progress" {
		t.Fatalf("check run calls: %+v", runs)
	}
	final := runs[1]
	if final.Conclusion != "failure" || len(final.Output.Annotations) != 1 || final.Output.Annotations[0].Path != "app/config.py" {
		t.Fatalf("check run result: %+v", final)
	}
	if strings.Contains(final.Output.Summary, pat) || strings.Contains(final.Output.Annotations[0].Message, pat) {
		t.Fatal("the check run contains the secret")
	}
	// The worker stored the PR finding through the incremental scan.
	list, err := db.ListSecrets(ctx, store.ListFilter{RuleID: "github-pat"})
	if err != nil || len(list) != 1 {
		t.Fatalf("stored PR finding: %d %v", len(list), err)
	}

	// 3. A finding marked as a false positive no longer fails the check.
	if err := db.Resolve(ctx, list[0].Fingerprint, store.StateFalsePositive, "tester", "test token"); err != nil {
		t.Fatal(err)
	}
	work.Write("app/other.py", "TOKEN = '"+pat+"'\n")
	head2 := work.Commit("copy token")
	work.Git("push", "-q", "-f", bare, "feature:refs/pull/1/head")
	sendPR(head2)
	if runs := gh.last(); len(runs) < 2 || runs[1].Conclusion != "success" {
		t.Fatalf("check run after false positive: %+v", runs)
	}

	// 4. Without new commits, a scan lists no blobs. A new cache version,
	// for example after a rule change, makes the scan cover the history
	// again.
	res, err := sw.ScanRepo(ctx, 101, false)
	if err != nil || res.Stats.BlobsListed != 0 {
		t.Fatalf("scan without new commits: %+v %v", res, err)
	}
	sw.Scanner = &scanner.Scanner{Engine: engine.New(set), Hasher: hasher, MaxBlobSize: scanner.DefaultMaxBlobSize - 1, Workers: 2}
	if res, err = sw.ScanRepo(ctx, 101, false); err != nil || res.Stats.BlobsListed == 0 {
		t.Fatalf("scan after a version change: %+v %v", res, err)
	}

	// 5. When Slack fails, the alert goes to the queue and the worker
	// sends it later.
	sink.mu.Lock()
	sink.down = true
	before := len(sink.msgs)
	sink.mu.Unlock()
	work.Git("checkout", "-q", "main")
	pemKey := testsecret.PrivateKey()
	work.Write("deploy/key.pem", pemKey)
	work.Commit("add key")
	work.Git("push", "-q", bare, "main:main")
	r, err := db.GetRepo(ctx, 101)
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.FetchRepo(ctx, r); err != nil {
		t.Fatal(err)
	}
	if res, err = sw.ScanRepo(ctx, 101, false); err != nil || len(res.NewSecrets) != 1 {
		t.Fatalf("scan with a new key: %+v %v", res, err)
	}
	sink.mu.Lock()
	sink.down = false
	sink.mu.Unlock()
	if ran, err := worker.RunOne(ctx); err != nil || !ran {
		t.Fatalf("notify job: ran %v err %v", ran, err)
	}
	sink.mu.Lock()
	msgs := sink.msgs[before:]
	sink.mu.Unlock()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "generic-private-key") || !strings.Contains(msgs[0], "owners @acme/sre") {
		t.Fatalf("retried alert: %q", msgs)
	}

	// 6. No token or secret reaches the logs, the mirror config or Slack.
	cfg, _ := os.ReadFile(filepath.Join(sw.Mirrors.RepoPath(101), "config"))
	for name, text := range map[string]string{"logs": logs.String(), "mirror config": string(cfg), "slack": strings.Join(sink.msgs, "\n")} {
		for _, secret := range []string{installationToken, awsSecret, keyID, pat, strings.Split(pemKey, "\n")[1]} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains a secret value", name)
			}
		}
	}
}
