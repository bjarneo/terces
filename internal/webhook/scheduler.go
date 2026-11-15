package webhook

import (
	"context"
	"log/slog"
	"time"

	"terces/internal/store"
)

// Scheduler queues the periodic jobs and recovers stale jobs. More than
// one scheduler can run: the store queues each periodic job one time.
type Scheduler struct {
	Store *store.Store
	Log   *slog.Logger
	// ReconcileHour is the UTC hour of the nightly reconcile. Webhooks get
	// dropped, so the reconcile syncs and scans everything.
	ReconcileHour int
	// DigestWeekday and DigestHour set the time of the weekly digest in UTC.
	DigestWeekday time.Weekday
	DigestHour    int
	// Digest turns the weekly digest on.
	Digest bool
	// Now returns the current time. Tests replace it.
	Now func() time.Time
	// MaxAttempts is the number of tries before a stale job is marked
	// failed. The default is 5, the same as the worker.
	MaxAttempts int
}

func (s *Scheduler) maxAttempts() int {
	if s.MaxAttempts > 0 {
		return s.MaxAttempts
	}
	return 5
}

func (s *Scheduler) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Run checks the schedule every minute until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	s.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick runs one schedule check.
func (s *Scheduler) Tick(ctx context.Context) {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	if n, err := s.Store.RequeueStaleJobs(ctx, 10*time.Minute, s.maxAttempts()); err != nil {
		s.log().Error("requeue stale jobs", "err", err)
	} else if n > 0 {
		s.log().Warn("requeued stale jobs", "count", n)
	}
	if now.Hour() == s.ReconcileHour {
		if ok, err := s.Store.EnqueueUnlessRecent(ctx, KindReconcile, 20*time.Hour, struct{}{}); err != nil {
			s.log().Error("queue reconcile", "err", err)
		} else if ok {
			s.log().Info("queued nightly reconcile")
		}
	}
	if s.Digest && now.Weekday() == s.DigestWeekday && now.Hour() == s.DigestHour {
		if ok, err := s.Store.EnqueueUnlessRecent(ctx, KindDigest, 6*24*time.Hour, struct{}{}); err != nil {
			s.log().Error("queue digest", "err", err)
		} else if ok {
			s.log().Info("queued weekly digest")
		}
	}
	if now.Minute() == 0 {
		if _, err := s.Store.PurgeJobs(ctx, 7*24*time.Hour); err != nil {
			s.log().Error("purge jobs", "err", err)
		}
	}
}
