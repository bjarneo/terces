// Package pipeline connects GitHub, the mirrors, the scanner, the store and
// the notifications. The CLI and the webhook worker share it.
package pipeline

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"terces/internal/githubapp"
	"terces/internal/mirror"
	"terces/internal/notify"
	"terces/internal/repoconfig"
	"terces/internal/scanner"
	"terces/internal/store"
)

// CheckName is the name of the check run on pull requests.
const CheckName = "terces"

// Pipeline runs sync, scans and pull request checks.
type Pipeline struct {
	Store   *store.Store
	GitHub  *githubapp.App
	Mirrors *mirror.Store
	Scanner *scanner.Scanner
	// Slack is nil when alerts are off.
	Slack *notify.Slack
	Log   *slog.Logger
	// Concurrency is the number of repositories that sync fetches at the
	// same time.
	Concurrency int
	// FetchTimeout limits the fetch of one repository. 0 means
	// DefaultFetchTimeout.
	FetchTimeout time.Duration

	locks keyedMutex
}

// keyedMutex serializes git work on one mirror.
type keyedMutex struct {
	mu sync.Mutex
	m  map[int64]*sync.Mutex
}

func (k *keyedMutex) lock(id int64) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[int64]*sync.Mutex{}
	}
	l, ok := k.m[id]
	if !ok {
		l = &sync.Mutex{}
		k.m[id] = l
	}
	k.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (sw *Pipeline) log() *slog.Logger {
	if sw.Log != nil {
		return sw.Log
	}
	return slog.Default()
}

// SyncOptions controls Sync.
type SyncOptions struct {
	// Org limits the sync to one org. Empty means all installations.
	Org string
	// InstallationID limits the sync to one installation.
	InstallationID int64
	// Scan runs an incremental scan after each fetch.
	Scan bool
}

// SyncSummary counts the work of a sync.
type SyncSummary struct {
	Installations int `json:"installations"`
	// InstallErrors counts installations whose repository list or store
	// update failed. Sync continues with the next installation.
	InstallErrors int `json:"installation_errors"`
	Repos         int `json:"repos"`
	Fetched       int `json:"fetched"`
	FetchErrors   int `json:"fetch_errors"`
	Removed       int `json:"removed"`
	Scanned       int `json:"scanned"`
	ScanErrors    int `json:"scan_errors"`
	Findings      int `json:"findings"`
	NewSecrets    int `json:"new_secrets"`
}

// Sync discovers installations and repositories, updates the store and
// fetches the mirrors.
func (sw *Pipeline) Sync(ctx context.Context, opts SyncOptions) (*SyncSummary, error) {
	if sw.GitHub == nil {
		return nil, errors.New("sync needs the GitHub App configuration")
	}
	var insts []githubapp.Installation
	if opts.InstallationID != 0 {
		inst, err := sw.GitHub.Installation(ctx, opts.InstallationID)
		if githubapp.IsNotFound(err) {
			// The app was uninstalled. Keep the findings, stop fetching.
			n, err := sw.Store.MarkRemovedExcept(ctx, opts.InstallationID, nil)
			return &SyncSummary{Removed: int(n)}, err
		}
		if err != nil {
			return nil, err
		}
		insts = []githubapp.Installation{*inst}
	} else {
		var err error
		if insts, err = sw.GitHub.Installations(ctx); err != nil {
			return nil, fmt.Errorf("list installations: %w", err)
		}
	}

	sum := &SyncSummary{}
	var lastErr error
	for _, inst := range insts {
		if opts.Org != "" && !strings.EqualFold(inst.Account.Login, opts.Org) {
			continue
		}
		if inst.SuspendedAt != nil {
			sw.log().Warn("skip suspended installation", "installation", inst.ID, "account", inst.Account.Login)
			continue
		}
		sum.Installations++
		if err := sw.syncInstallation(ctx, inst, opts, sum); err != nil {
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			// One org with a problem, such as an IP allow list, must not
			// stop the sync of the other orgs.
			sum.InstallErrors++
			lastErr = err
			sw.log().Error("sync installation failed", "installation", inst.ID, "account", inst.Account.Login, "err", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return sum, err
	}
	if sum.InstallErrors > 0 && sum.InstallErrors == sum.Installations {
		return sum, fmt.Errorf("sync failed for all %d installations: %w", sum.Installations, lastErr)
	}
	return sum, nil
}

// syncInstallation updates the repositories of one installation, then
// fetches and scans them. It adds its counts to sum.
func (sw *Pipeline) syncInstallation(ctx context.Context, inst githubapp.Installation, opts SyncOptions, sum *SyncSummary) error {
	repos, err := sw.GitHub.Repositories(ctx, inst.ID)
	if err != nil {
		return fmt.Errorf("list repositories of %s: %w", inst.Account.Login, err)
	}
	type item struct {
		repo  *store.Repo
		fetch bool
	}
	var ids []int64
	var work []item
	var upsertErr error
	for _, gr := range repos {
		r := RepoFromGitHub(gr, inst.ID)
		// The repository exists on GitHub, also when its store update
		// fails. Keep its ID, so that it is not marked as removed.
		ids = append(ids, r.ID)
		sum.Repos++
		res, err := sw.Store.UpsertRepo(ctx, r)
		if err != nil {
			upsertErr = err
			sw.log().Error("store repository failed", "repo", r.FullName(), "err", err)
			continue
		}
		// An archived repository gets one last fetch when it becomes
		// archived. After that the mirror stays as it is, but a new rules
		// version still scans it again.
		fetch := !r.Archived || res.Created || !res.WasArchived || !sw.Mirrors.Exists(sw.Mirrors.RepoPath(r.ID))
		work = append(work, item{r, fetch})
	}
	if upsertErr == nil {
		n, err := sw.Store.MarkRemovedExcept(ctx, inst.ID, ids)
		if err != nil {
			return err
		}
		sum.Removed += int(n)
	}

	conc := sw.Concurrency
	if conc <= 0 {
		conc = 4
	}
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, it := range work {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(r *store.Repo, fetch bool) {
			defer wg.Done()
			defer func() { <-sem }()
			if fetch {
				err := sw.FetchRepo(ctx, r)
				mu.Lock()
				if err != nil {
					sum.FetchErrors++
					mu.Unlock()
					sw.log().Error("fetch failed", "repo", r.FullName(), "err", err)
					return
				}
				sum.Fetched++
				mu.Unlock()
			}
			if !opts.Scan {
				return
			}
			res, err := sw.ScanRepo(ctx, r.ID, false)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				sum.ScanErrors++
				sw.log().Error("scan failed", "repo", r.FullName(), "err", err)
				return
			}
			sum.Scanned++
			sum.Findings += len(res.Findings)
			sum.NewSecrets += len(res.NewSecrets)
		}(it.repo, it.fetch)
	}
	wg.Wait()
	return upsertErr
}

// DefaultFetchTimeout is the time limit for the fetch of one repository
// when Pipeline.FetchTimeout is 0.
const DefaultFetchTimeout = time.Hour

// FetchRepo creates or updates the mirrors of a repository and its wiki.
// The fetch has a time limit, so a stalled fetch fails and frees its
// worker.
func (sw *Pipeline) FetchRepo(ctx context.Context, r *store.Repo) error {
	limit := sw.FetchTimeout
	if limit <= 0 {
		limit = DefaultFetchTimeout
	}
	fctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	err := sw.fetchRepo(fctx, r)
	if err != nil && ctx.Err() == nil && errors.Is(fctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("fetch of %s took longer than %s: %w", r.FullName(), limit, err)
	}
	return err
}

// RepoFromGitHub converts an API repository to a store row.
func RepoFromGitHub(gr githubapp.Repository, installationID int64) *store.Repo {
	org, name, ok := strings.Cut(gr.FullName, "/")
	if !ok {
		org, name = gr.Owner.Login, gr.Name
	}
	return &store.Repo{
		ID:             gr.ID,
		Org:            org,
		Name:           name,
		InstallationID: installationID,
		DefaultBranch:  gr.DefaultBranch,
		HasWiki:        gr.HasWiki,
		Private:        gr.Private,
		Archived:       gr.Archived,
	}
}

func (sw *Pipeline) fetchRepo(ctx context.Context, r *store.Repo) error {
	if sw.GitHub == nil {
		return errors.New("fetch needs the GitHub App configuration")
	}
	if r.InstallationID == 0 {
		return fmt.Errorf("%s has no installation: run sync", r.FullName())
	}
	unlock := sw.locks.lock(r.ID)
	defer unlock()

	tok, err := sw.GitHub.Token(ctx, r.InstallationID)
	if err != nil {
		return err
	}
	if err := sw.Mirrors.Fetch(ctx, sw.Mirrors.RepoPath(r.ID), mirror.FetchOptions{
		FullName: r.FullName(), Token: tok, DefaultBranch: r.DefaultBranch,
	}); err != nil {
		return err
	}
	if r.HasWiki {
		wiki := sw.Mirrors.WikiPath(r.ID)
		had := sw.Mirrors.Exists(wiki)
		err := sw.Mirrors.Fetch(ctx, wiki, mirror.FetchOptions{FullName: r.FullName(), Token: tok, Wiki: true})
		switch {
		case err != nil && had:
			sw.log().Warn("wiki fetch failed", "repo", r.FullName(), "err", err)
		case err != nil:
			// GitHub has no wiki repository until the first page exists.
			sw.log().Debug("no wiki", "repo", r.FullName())
		}
	}
	return sw.Store.SetFetched(ctx, r.ID)
}

// ScanResult is the result of one repository scan.
type ScanResult struct {
	Repo         *store.Repo       `json:"-"`
	Findings     []scanner.Finding `json:"findings"`
	NewSecrets   []scanner.Finding `json:"new_secrets"`
	NewLocations int               `json:"new_locations"`
	Stats        *scanner.Stats    `json:"stats"`
}

// ScanRepo scans the mirror of a repository and its wiki. Without full, it
// leaves out the history that the last scan covered. It stores the
// findings and sends alerts for new secrets.
func (sw *Pipeline) ScanRepo(ctx context.Context, repoID int64, full bool) (*ScanResult, error) {
	unlock := sw.locks.lock(repoID)
	defer unlock()

	r, err := sw.Store.GetRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	path := sw.Mirrors.RepoPath(r.ID)
	if !sw.Mirrors.Exists(path) {
		return nil, fmt.Errorf("%s has no mirror: run `terces sync`", r.FullName())
	}
	res := &ScanResult{Repo: r, Stats: &scanner.Stats{}}
	tips := &store.Tips{}
	// A new cache version means new rules, a new engine or a new key. The
	// scan then covers the full history again, not only the new commits.
	version := sw.Scanner.Version()
	tips.Version = version
	var old store.Tips
	if r.Tips != nil && !full && r.Tips.Version == version {
		old = *r.Tips
	}

	g := sw.Mirrors.Git(path)
	cfg, err := scanner.LoadConfig(ctx, g, "HEAD")
	if err != nil {
		sw.log().Warn("ignore invalid repository config", "repo", r.FullName(), "err", err)
		cfg = nil
	}
	if tips.Repo, err = g.Tips(ctx); err != nil {
		return nil, err
	}
	fs, st, err := sw.scanMirror(ctx, g, store.Values(old.Repo), "", cfg)
	if err != nil {
		return nil, err
	}
	res.Findings = append(res.Findings, fs...)
	res.Stats.Add(st)

	wiki := sw.Mirrors.WikiPath(r.ID)
	if sw.Mirrors.Exists(wiki) {
		wg := sw.Mirrors.Git(wiki)
		if tips.Wiki, err = wg.Tips(ctx); err != nil {
			return nil, err
		}
		fs, st, err := sw.scanMirror(ctx, wg, store.Values(old.Wiki), "wiki:", cfg)
		if err != nil {
			return nil, err
		}
		res.Findings = append(res.Findings, fs...)
		res.Stats.Add(st)
	}

	rec, err := sw.Store.RecordFindings(ctx, r.ID, res.Findings)
	if err != nil {
		return nil, err
	}
	res.NewSecrets = rec.NewSecrets
	res.NewLocations = rec.NewLocations
	if err := sw.Store.SetScanned(ctx, r.ID, tips); err != nil {
		return nil, err
	}
	sw.log().Info("scanned", "repo", r.FullName(), "findings", len(res.Findings),
		"new_secrets", len(res.NewSecrets), "new_locations", res.NewLocations, "stats", res.Stats.Summary())

	if sw.Slack != nil && len(res.NewSecrets) > 0 {
		if err := sw.SendAlert(ctx, r.ID, res.NewSecrets); err != nil {
			// The secrets are no longer new on the next scan. Queue the
			// alert, so that the worker sends it later.
			sw.log().Error("slack alert failed, queued for retry", "repo", r.FullName(), "err", err)
			if _, qerr := sw.Store.Enqueue(ctx, KindNotify, "", NotifyJob{RepoID: r.ID, Findings: res.NewSecrets}); qerr != nil {
				sw.log().Error("queue slack alert", "repo", r.FullName(), "err", qerr)
			}
		}
	}
	return res, nil
}

// KindNotify is the job kind for a Slack alert that failed before.
const KindNotify = "notify"

// NotifyJob is the payload of a notify job. It holds no plaintext.
type NotifyJob struct {
	RepoID   int64             `json:"repo_id"`
	Findings []scanner.Finding `json:"findings"`
}

// SendAlert posts the Slack alert for new secrets in a repository. It
// reads the owners from CODEOWNERS on the default branch of the mirror.
func (sw *Pipeline) SendAlert(ctx context.Context, repoID int64, findings []scanner.Finding) error {
	if sw.Slack == nil || len(findings) == 0 {
		return nil
	}
	r, err := sw.Store.GetRepo(ctx, repoID)
	if err != nil {
		return err
	}
	for i := range findings {
		if len(findings[i].Fingerprint) == 0 && findings[i].FPHex != "" {
			findings[i].Fingerprint, _ = hex.DecodeString(findings[i].FPHex)
		}
	}
	var owners *notify.Codeowners
	if path := sw.Mirrors.RepoPath(r.ID); sw.Mirrors.Exists(path) {
		owners = sw.codeowners(ctx, sw.Mirrors.Git(path))
	}
	return sw.Slack.NewFindings(ctx, notify.RepoRef{Org: r.Org, Name: r.Name}, findings, owners)
}

func (sw *Pipeline) scanMirror(ctx context.Context, g *mirror.Git, exclude []string, prefix string, cfg *repoconfig.Config) ([]scanner.Finding, *scanner.Stats, error) {
	return sw.Scanner.ScanHistory(ctx, g, scanner.HistoryOptions{
		Exclude:    exclude,
		Cache:      sw.Store,
		Config:     cfg,
		PathPrefix: prefix,
	})
}

func (sw *Pipeline) codeowners(ctx context.Context, g *mirror.Git) *notify.Codeowners {
	for _, p := range notify.CodeownersPaths {
		if data, err := g.ReadFile(ctx, "HEAD", p); err == nil && data != nil {
			return notify.ParseCodeowners(data)
		}
	}
	return nil
}
