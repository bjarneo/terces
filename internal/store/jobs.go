package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Job is one unit of work in the queue.
type Job struct {
	ID       int64
	Kind     string
	Payload  json.RawMessage
	Attempts int
}

// Enqueue adds a job. When dedupeKey is not empty and a queued job with
// the same kind and key exists, Enqueue adds nothing and returns false.
func (s *Store) Enqueue(ctx context.Context, kind, dedupeKey string, payload any) (bool, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `insert into jobs (kind, dedupe_key, payload) values ($1, nullif($2, ''), $3)
		on conflict (kind, dedupe_key) where state = 'queued' do nothing`, kind, dedupeKey, data)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// EnqueueUnlessRecent adds a job when no job of the same kind was created
// within the duration. The scheduler uses it for the nightly reconcile and
// the weekly digest.
func (s *Store) EnqueueUnlessRecent(ctx context.Context, kind string, within time.Duration, payload any) (bool, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	added := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtext('terces-schedule:' || $1))`, kind); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `insert into jobs (kind, payload) select $1, $2
			where not exists (select 1 from jobs where kind = $1 and created_at > now() - make_interval(secs => $3))`,
			kind, data, within.Seconds())
		added = tag.RowsAffected() == 1
		return err
	})
	return added, err
}

// ClaimJob locks the next ready job and marks it as running. It returns
// nil when no job is ready. Concurrent workers never get the same job.
func (s *Store) ClaimJob(ctx context.Context) (*Job, error) {
	var j Job
	err := s.pool.QueryRow(ctx, `
		update jobs set state = 'running', locked_at = now(), attempts = attempts + 1, updated_at = now()
		where id = (
			select id from jobs where state = 'queued' and run_after <= now()
			order by run_after, id
			for update skip locked
			limit 1)
		returning id, kind, payload, attempts`).Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// HeartbeatJob tells the queue that a running job is still alive.
func (s *Store) HeartbeatJob(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `update jobs set locked_at = now() where id = $1 and state = 'running'`, id)
	return err
}

// CompleteJob marks a job as done.
func (s *Store) CompleteJob(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `update jobs set state = 'done', locked_at = null, last_error = null, updated_at = now() where id = $1`, id)
	return err
}

// FailJob records an error. When retryIn is positive, the job goes back to
// the queue. Otherwise it is marked as failed.
func (s *Store) FailJob(ctx context.Context, id int64, jobErr error, retryIn time.Duration) error {
	msg := jobErr.Error()
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	if retryIn > 0 {
		_, err := s.pool.Exec(ctx, `update jobs set state = 'queued', locked_at = null, last_error = $2,
			run_after = now() + make_interval(secs => $3), updated_at = now() where id = $1`, id, msg, retryIn.Seconds())
		if err != nil && isUniqueViolation(err) {
			// A queued job with the same dedupe key exists. It covers
			// the retry.
			_, err = s.pool.Exec(ctx, `update jobs set state = 'failed', locked_at = null, last_error = $2, updated_at = now() where id = $1`, id, msg)
		}
		return err
	}
	_, err := s.pool.Exec(ctx, `update jobs set state = 'failed', locked_at = null, last_error = $2, updated_at = now() where id = $1`, id, msg)
	return err
}

// RequeueStaleJobs recovers the jobs of a crashed worker. A running job
// is stale when its last heartbeat is older than the duration.
//
// For each kind and dedupe key, the newest stale job goes back to the
// queue. A stale job is marked as failed when a queued job with the same
// key already covers it, when a newer stale job covers it, or when it has
// used maxAttempts attempts. A job that crashes the worker each time then
// stops after maxAttempts tries.
func (s *Store) RequeueStaleJobs(ctx context.Context, olderThan time.Duration, maxAttempts int) (int64, error) {
	var requeued int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `select id, kind, coalesce(dedupe_key, ''), attempts from jobs
			where state = 'running' and locked_at < now() - make_interval(secs => $1)
			order by id desc
			for update skip locked`, olderThan.Seconds())
		if err != nil {
			return err
		}
		type stale struct {
			id       int64
			kind     string
			key      string
			attempts int
		}
		var list []stale
		for rows.Next() {
			var j stale
			if err := rows.Scan(&j.id, &j.kind, &j.key, &j.attempts); err != nil {
				rows.Close()
				return err
			}
			list = append(list, j)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		taken := map[string]bool{}
		for _, j := range list {
			reason := ""
			group := j.kind + "\x00" + j.key
			switch {
			case j.attempts >= maxAttempts:
				reason = "the worker stopped during each attempt"
			case j.key != "" && taken[group]:
				reason = "a newer job with the same key covers this job"
			case j.key != "":
				var queued bool
				if err := tx.QueryRow(ctx, `select exists (select 1 from jobs where state = 'queued' and kind = $1 and dedupe_key = $2)`,
					j.kind, j.key).Scan(&queued); err != nil {
					return err
				}
				if queued {
					reason = "a queued job with the same key covers this job"
				}
			}
			if reason != "" {
				if _, err := tx.Exec(ctx, `update jobs set state = 'failed', locked_at = null, last_error = $2, updated_at = now() where id = $1`,
					j.id, reason); err != nil {
					return err
				}
				continue
			}
			if j.key != "" {
				taken[group] = true
			}
			if _, err := tx.Exec(ctx, `update jobs set state = 'queued', locked_at = null, updated_at = now() where id = $1`, j.id); err != nil {
				return err
			}
			requeued++
		}
		return nil
	})
	return requeued, err
}

// PurgeJobs deletes finished jobs that are older than the duration.
func (s *Store) PurgeJobs(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `delete from jobs where state in ('done', 'failed')
		and updated_at < now() - make_interval(secs => $1)`, olderThan.Seconds())
	return tag.RowsAffected(), err
}

// JobCounts returns the number of jobs in each state.
func (s *Store) JobCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `select state, count(*) from jobs group by state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
