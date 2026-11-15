package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"terces/internal/pipeline"
	"terces/internal/store"
)

// Worker runs queued jobs.
type Worker struct {
	Store    *store.Store
	Pipeline *pipeline.Pipeline
	Log      *slog.Logger
	// Concurrency is the number of jobs that run at the same time.
	Concurrency int
	// PollInterval is the wait time when the queue is empty.
	PollInterval time.Duration
	// MaxAttempts is the number of tries before a job is marked failed.
	MaxAttempts int
}

func (w *Worker) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// Run starts the workers and blocks until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	n := w.Concurrency
	if n <= 0 {
		n = 2
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.loop(ctx)
		}()
	}
	wg.Wait()
}

func (w *Worker) loop(ctx context.Context) {
	poll := w.PollInterval
	if poll <= 0 {
		poll = 2 * time.Second
	}
	for ctx.Err() == nil {
		ran, err := w.RunOne(ctx)
		if err != nil && ctx.Err() == nil {
			w.log().Error("job queue", "err", err)
		}
		if !ran {
			select {
			case <-ctx.Done():
			case <-time.After(poll):
			}
		}
	}
}

// RunOne claims and runs one job. It reports whether a job ran.
func (w *Worker) RunOne(ctx context.Context) (bool, error) {
	job, err := w.Store.ClaimJob(ctx)
	if err != nil || job == nil {
		return false, err
	}
	log := w.log().With("job", job.ID, "kind", job.Kind, "attempt", job.Attempts)
	start := time.Now()

	// The heartbeat keeps long jobs, such as the nightly reconcile, from
	// being taken for a crashed worker.
	hbCtx, stopHB := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				if err := w.Store.HeartbeatJob(hbCtx, job.ID); err != nil && hbCtx.Err() == nil {
					log.Warn("job heartbeat", "err", err)
				}
			}
		}
	}()
	err = w.handle(ctx, job)
	stopHB()

	// Record the result even when ctx ends.
	bg := context.WithoutCancel(ctx)
	if err == nil {
		log.Info("job done", "duration", time.Since(start).Round(time.Millisecond))
		return true, w.Store.CompleteJob(bg, job.ID)
	}
	max := w.MaxAttempts
	if max <= 0 {
		max = 5
	}
	var perm permanentError
	retry := time.Duration(0)
	if !errors.As(err, &perm) && job.Attempts < max {
		retry = time.Duration(1<<job.Attempts) * time.Minute
		if retry > time.Hour {
			retry = time.Hour
		}
	}
	log.Error("job failed", "err", err, "retry_in", retry)
	return true, w.Store.FailJob(bg, job.ID, err, retry)
}

type permanentError struct{ error }

func (w *Worker) handle(ctx context.Context, job *store.Job) error {
	sw := w.Pipeline
	switch job.Kind {
	case KindSyncInstallation:
		var p InstallationJob
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			return permanentError{err}
		}
		sum, err := sw.Sync(ctx, pipeline.SyncOptions{InstallationID: p.InstallationID, Scan: true})
		if err != nil {
			return err
		}
		w.log().Info("installation synced", "installation", p.InstallationID, "repos", sum.Repos, "removed", sum.Removed, "new_secrets", sum.NewSecrets)
		return nil

	case KindScanRepo:
		var p RepoJob
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			return permanentError{err}
		}
		r, err := w.ensureRepo(ctx, p)
		if err != nil {
			return err
		}
		if err := sw.FetchRepo(ctx, r); err != nil {
			return err
		}
		_, err = sw.ScanRepo(ctx, r.ID, false)
		return err

	case KindScanPR:
		var p RepoJob
		if err := json.Unmarshal(job.Payload, &p); err != nil || p.PR == nil {
			return permanentError{fmt.Errorf("invalid payload: %v", err)}
		}
		r, err := w.ensureRepo(ctx, p)
		if err != nil {
			return err
		}
		res, err := sw.CheckPullRequest(ctx, r, *p.PR)
		if err != nil {
			return err
		}
		w.log().Info("pull request checked", "repo", r.FullName(), "pr", p.PR.Number, "conclusion", res.Conclusion, "findings", len(res.Findings))
		return nil

	case KindRepoUpdate:
		var p RepoJob
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			return permanentError{err}
		}
		return w.updateRepo(ctx, p)

	case KindReconcile:
		sum, err := sw.Sync(ctx, pipeline.SyncOptions{Scan: true})
		if err != nil {
			return err
		}
		w.log().Info("reconcile done", "repos", sum.Repos, "fetched", sum.Fetched, "fetch_errors", sum.FetchErrors,
			"scanned", sum.Scanned, "scan_errors", sum.ScanErrors, "new_secrets", sum.NewSecrets)
		return nil

	case pipeline.KindNotify:
		var p pipeline.NotifyJob
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			return permanentError{err}
		}
		return sw.SendAlert(ctx, p.RepoID, p.Findings)

	case KindDigest:
		if sw.Slack == nil {
			return nil
		}
		d, err := w.Store.Digest(ctx)
		if err != nil {
			return err
		}
		return sw.Slack.Digest(ctx, d)
	}
	return permanentError{fmt.Errorf("unknown job kind %q", job.Kind)}
}

// ensureRepo returns the stored repository and creates it from the job
// payload when it is new.
func (w *Worker) ensureRepo(ctx context.Context, p RepoJob) (*store.Repo, error) {
	r, err := w.Store.GetRepo(ctx, p.Repo.ID)
	if err == nil && r.RemovedAt == nil && r.InstallationID != 0 {
		return r, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	// Some payloads, such as installation_repositories, hold only the
	// name. Get the default branch, the wiki flag and the archived flag
	// from the API.
	if p.Repo.DefaultBranch == "" && p.Repo.FullName != "" && w.Pipeline.GitHub != nil {
		full, err := w.Pipeline.GitHub.Repository(ctx, p.InstallationID, p.Repo.FullName)
		if err != nil {
			return nil, fmt.Errorf("get repository metadata: %w", err)
		}
		p.Repo = *full
	}
	nr := pipeline.RepoFromGitHub(p.Repo, p.InstallationID)
	if nr.Org == "" || nr.Name == "" {
		return nil, permanentError{fmt.Errorf("repository %d has no name in the payload", p.Repo.ID)}
	}
	if _, err := w.Store.UpsertRepo(ctx, nr); err != nil {
		return nil, err
	}
	return w.Store.GetRepo(ctx, nr.ID)
}

func (w *Worker) updateRepo(ctx context.Context, p RepoJob) error {
	switch p.Action {
	case "deleted", "removed":
		return w.Store.MarkRemoved(ctx, p.Repo.ID)
	case "created":
		r, err := w.ensureRepo(ctx, p)
		if err != nil {
			return err
		}
		if err := w.Pipeline.FetchRepo(ctx, r); err != nil {
			return err
		}
		_, err = w.Pipeline.ScanRepo(ctx, r.ID, false)
		return err
	}
	// The payload of renamed, transferred, archived and the other actions
	// holds the full repository object.
	nr := pipeline.RepoFromGitHub(p.Repo, p.InstallationID)
	res, err := w.Store.UpsertRepo(ctx, nr)
	if err != nil {
		return err
	}
	if p.Action == "archived" && !res.WasArchived {
		// Fetch and scan one last time. Then the mirror stays as it is.
		r, err := w.Store.GetRepo(ctx, nr.ID)
		if err != nil {
			return err
		}
		if err := w.Pipeline.FetchRepo(ctx, r); err != nil {
			return err
		}
		_, err = w.Pipeline.ScanRepo(ctx, r.ID, false)
		return err
	}
	return nil
}
