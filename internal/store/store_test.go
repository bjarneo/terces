package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"terces/internal/dbtest"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/store"
)

func TestMigrateIsIdempotent(t *testing.T) {
	s, _ := dbtest.New(t)
	ctx := context.Background()
	applied, err := s.Migrate(ctx)
	if err != nil || len(applied) != 0 {
		t.Fatalf("second migrate: applied %v, err %v", applied, err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestReposAndFindings(t *testing.T) {
	s, _ := dbtest.New(t)
	ctx := context.Background()

	for _, r := range []*store.Repo{
		{ID: 1, Org: "acme", Name: "api", InstallationID: 10, DefaultBranch: "main"},
		{ID: 2, Org: "acme", Name: "web", InstallationID: 10},
		{ID: 3, Org: "other", Name: "tool", InstallationID: 20},
	} {
		res, err := s.UpsertRepo(ctx, r)
		if err != nil || !res.Created {
			t.Fatalf("upsert %d: %+v %v", r.ID, res, err)
		}
	}
	// A rename keeps the ID, so the row stays the same.
	if _, err := s.UpsertRepo(ctx, &store.Repo{ID: 1, Org: "acme", Name: "api-v2", InstallationID: 10, Archived: true}); err != nil {
		t.Fatal(err)
	}
	r, err := s.FindRepo(ctx, "ACME", "api-v2")
	if err != nil || r.ID != 1 || !r.Archived || r.DefaultBranch != "main" {
		t.Fatalf("find renamed repo: %+v %v", r, err)
	}
	if n, err := s.MarkRemovedExcept(ctx, 10, []int64{1}); err != nil || n != 1 {
		t.Fatalf("mark removed: %d %v", n, err)
	}
	repos, _ := s.ListRepos(ctx, "acme", false)
	if len(repos) != 1 {
		t.Errorf("active acme repos = %d, want 1", len(repos))
	}

	fp := []byte("0123456789abcdef0123456789abcdef")
	f := scanner.Finding{Fingerprint: fp, RuleID: "github-pat", Severity: rules.SeverityMedium, Preview: "ghp_… (40)",
		Path: "a.txt", Line: 3, BlobSHA: "b1", CommitSHA: "c1", AuthorEmail: "dev@example.com", CommittedAt: "2025-01-02T03:04:05Z"}
	res, err := s.RecordFindings(ctx, 1, []scanner.Finding{f})
	if err != nil || len(res.NewSecrets) != 1 || res.NewLocations != 1 {
		t.Fatalf("first record: %+v %v", res, err)
	}
	// The same secret in a second repository is one secret with two
	// locations. A higher severity raises the severity of the secret.
	f2 := f
	f2.Path, f2.BlobSHA, f2.Severity = "b.txt", "b2", rules.SeverityCritical
	res, err = s.RecordFindings(ctx, 3, []scanner.Finding{f2, f})
	if err != nil || len(res.NewSecrets) != 0 || res.NewLocations != 2 {
		t.Fatalf("second record: %+v %v", res, err)
	}
	res, err = s.RecordFindings(ctx, 3, []scanner.Finding{f2})
	if err != nil || res.NewLocations != 0 {
		t.Fatalf("repeat record: %+v %v", res, err)
	}

	list, err := s.ListSecrets(ctx, store.ListFilter{State: "open", MinSeverity: rules.SeverityHigh})
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	if list[0].Severity != "critical" || list[0].Locations != 3 || len(list[0].Repos) != 2 {
		t.Errorf("list row: %+v", list[0])
	}
	if list[0].IntroducedAt == nil || list[0].IntroducedAt.Year() != 2025 {
		t.Errorf("introduced at: %v", list[0].IntroducedAt)
	}
	if got, _ := s.ListSecrets(ctx, store.ListFilter{Org: "other"}); len(got) != 1 || len(got[0].Repos) != 1 {
		t.Errorf("org filter: %+v", got)
	}

	full, err := s.ResolveFingerprint(ctx, list[0].FPHex[:10])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveFingerprint(ctx, "abc"); err == nil {
		t.Error("short prefix: want an error")
	}
	if err := s.Resolve(ctx, full, "revoked", "alice", "rotated"); err != nil {
		t.Fatal(err)
	}
	sec, locs, err := s.GetSecret(ctx, full)
	if err != nil || sec.State != "revoked" || sec.ResolvedBy != "alice" || len(locs) != 3 {
		t.Fatalf("get secret: %+v %d %v", sec, len(locs), err)
	}
	states, _ := s.SecretStates(ctx, [][]byte{fp, []byte("unknown")})
	if states[string(fp)] != "revoked" || len(states) != 1 {
		t.Errorf("states: %v", states)
	}
	if err := s.Resolve(ctx, []byte("missing"), "revoked", "alice", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("resolve missing: %v", err)
	}
	if rows, _ := s.Report(ctx, ""); len(rows) != 0 {
		t.Errorf("report after revoke: %d rows, want 0", len(rows))
	}
	if err := s.Resolve(ctx, full, "open", "alice", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Report(ctx, "")
	if err != nil || len(rows) != 2 {
		t.Fatalf("report: %d rows %v", len(rows), err)
	}
	d, err := s.Digest(ctx)
	if err != nil || d.Open != 1 || d.ByAge[0].Count != 1 || len(d.Oldest) != 1 {
		t.Fatalf("digest: %+v %v", d, err)
	}
}

func TestBlobCache(t *testing.T) {
	s, _ := dbtest.New(t)
	ctx := context.Background()
	res := map[string]scanner.BlobResult{
		"clean":  {},
		"dirty":  {Findings: []scanner.BlobFinding{{Fingerprint: []byte("fp1"), RuleID: "r1", Severity: rules.SeverityHigh, Preview: "p", Line: 4, PathAllow: []int{0, 2}}}},
		"capped": {Capped: true},
	}
	if err := s.Save(ctx, 7, res); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, 7, []string{"clean", "dirty", "capped", "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || len(got["clean"].Findings) != 0 || len(got["dirty"].Findings) != 1 || got["dirty"].Capped || !got["capped"].Capped {
		t.Fatalf("lookup: %+v", got)
	}
	if bf := got["dirty"].Findings[0]; bf.Line != 4 || len(bf.PathAllow) != 2 || bf.PathAllow[1] != 2 || bf.Severity != rules.SeverityHigh {
		t.Errorf("blob finding: %+v", bf)
	}
	// A new version misses the cache.
	if got, _ := s.Lookup(ctx, 8, []string{"clean", "dirty"}); len(got) != 0 {
		t.Errorf("new version: %d hits, want 0", len(got))
	}
	// Saving with the new version replaces the old rows.
	if err := s.Save(ctx, 8, map[string]scanner.BlobResult{"dirty": {}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Lookup(ctx, 8, []string{"dirty"}); len(got["dirty"].Findings) != 0 {
		t.Errorf("replaced blob: %+v", got)
	}
}

func TestJobQueue(t *testing.T) {
	s, _ := dbtest.New(t)
	ctx := context.Background()
	ok, err := s.Enqueue(ctx, "scan_repo", "1", map[string]int{"id": 1})
	if err != nil || !ok {
		t.Fatalf("enqueue: %v %v", ok, err)
	}
	if ok, _ := s.Enqueue(ctx, "scan_repo", "1", nil); ok {
		t.Error("duplicate queued job: want no new job")
	}
	job, err := s.ClaimJob(ctx)
	if err != nil || job == nil || job.Kind != "scan_repo" || job.Attempts != 1 {
		t.Fatalf("claim: %+v %v", job, err)
	}
	// The running job frees the dedupe key, so a new push queues again.
	if ok, _ := s.Enqueue(ctx, "scan_repo", "1", nil); !ok {
		t.Error("enqueue while running: want a new job")
	}
	if j2, _ := s.ClaimJob(ctx); j2 == nil || j2.ID == job.ID {
		t.Fatalf("second claim: %+v", j2)
	} else if err := s.CompleteJob(ctx, j2.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FailJob(ctx, job.ID, errors.New("boom"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if j, _ := s.ClaimJob(ctx); j != nil {
		t.Errorf("job with run_after in the future was claimed: %+v", j)
	}
	if ok, _ := s.EnqueueUnlessRecent(ctx, "reconcile", time.Hour, nil); !ok {
		t.Error("first reconcile: want a job")
	}
	if ok, _ := s.EnqueueUnlessRecent(ctx, "reconcile", time.Hour, nil); ok {
		t.Error("second reconcile within the hour: want no job")
	}
	counts, _ := s.JobCounts(ctx)
	if counts["done"] != 1 || counts["queued"] != 2 {
		t.Errorf("counts: %v", counts)
	}
}

func TestStaleJobsWithTheSameKey(t *testing.T) {
	s, dsn := dbtest.New(t)
	ctx := context.Background()
	// Two running jobs with the same key, as after a crash during a push
	// burst, plus one unrelated job and one job without attempts left.
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, key := range []string{"42", "42", "99", "77"} {
		if _, err := s.Enqueue(ctx, "scan_repo", key, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ClaimJob(ctx); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(t, dsn, `update jobs set locked_at = now() - interval '1 hour'`)
	execSQL(t, dsn, `update jobs set attempts = 5 where dedupe_key = '77'`)
	n, err := s.RequeueStaleJobs(ctx, 10*time.Minute, 5)
	if err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if n != 2 {
		t.Errorf("requeued %d jobs, want 2: one for key 42 and one for key 99", n)
	}
	counts, _ := s.JobCounts(ctx)
	if counts["queued"] != 2 || counts["failed"] != 2 || counts["running"] != 0 {
		t.Errorf("counts: %v", counts)
	}
}

func TestRemovedAndRecreatedRepos(t *testing.T) {
	s, _ := dbtest.New(t)
	ctx := context.Background()
	if _, err := s.UpsertRepo(ctx, &store.Repo{ID: 1, Org: "acme", Name: "api", InstallationID: 5}); err != nil {
		t.Fatal(err)
	}
	// An uninstalled app lists no repositories.
	if n, err := s.MarkRemovedExcept(ctx, 5, nil); err != nil || n != 1 {
		t.Fatalf("mark removed with no repositories: %d %v", n, err)
	}
	if _, err := s.UpsertRepo(ctx, &store.Repo{ID: 2, Org: "acme", Name: "api", InstallationID: 6}); err != nil {
		t.Fatal(err)
	}
	r, err := s.FindRepo(ctx, "acme", "api")
	if err != nil || r.ID != 2 {
		t.Fatalf("find repo: %+v %v, want the active repository 2", r, err)
	}
}

func execSQL(t *testing.T, dsn, sql string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatal(err)
	}
}

// Repository content is untrusted. A path with invalid UTF-8 or a path
// longer than the btree limit must not fail the transaction, because the
// transaction holds all findings of the repository.
func TestRecordFindingsWithHostilePaths(t *testing.T) {
	s, _ := dbtest.New(t)
	ctx := context.Background()
	if _, err := s.UpsertRepo(ctx, &store.Repo{ID: 1, Org: "acme", Name: "api", InstallationID: 1}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("deep/", 600) + "x.env"
	fp := []byte("hostile-path-fingerprint-0123456")
	var fs []scanner.Finding
	for i, p := range []string{"caf\xe9.env", long, "a\x1b[2Kb.env", "normal.env"} {
		fs = append(fs, scanner.Finding{Fingerprint: fp, RuleID: "github-pat", Severity: rules.SeverityHigh,
			Preview: "ghp_… (40)", Path: p, Line: i + 1, BlobSHA: "b1", AuthorEmail: "x\xff@example.com"})
	}
	res, err := s.RecordFindings(ctx, 1, fs)
	if err != nil {
		t.Fatalf("record hostile paths: %v", err)
	}
	if res.NewLocations != 4 {
		t.Errorf("new locations = %d, want 4", res.NewLocations)
	}
	_, locs, err := s.GetSecret(ctx, fp)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, l := range locs {
		paths[l.Path] = true
		if !utf8.ValidString(l.Path) || strings.ContainsRune(l.Path, 0x1b) || !utf8.ValidString(l.AuthorEmail) {
			t.Errorf("stored path %q or email %q is not safe text", l.Path, l.AuthorEmail)
		}
	}
	if !paths[`"caf\xe9.env"`] || !paths["normal.env"] || !paths[long] {
		t.Errorf("stored paths: %v", paths)
	}
	// Recording again adds no location.
	if res, err := s.RecordFindings(ctx, 1, fs); err != nil || res.NewLocations != 0 {
		t.Errorf("second record: %+v %v", res, err)
	}
}
