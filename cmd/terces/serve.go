package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"terces/internal/webhook"
)

var weekdays = map[string]time.Weekday{
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday,
	"thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday,
}

func newServeCmd(a *app) *cobra.Command {
	var listen, secretFile, digestDay string
	var jobWorkers, reconcileHour, digestHour int
	var noWorker bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the webhook listener, the job workers and the scheduler",
		Long: "Run the webhook listener, the job workers and the scheduler.\n\n" +
			"The listener verifies X-Hub-Signature-256 on each delivery, queues a job\n" +
			"in Postgres and answers at once. The workers fetch mirrors, scan new\n" +
			"commits and post check runs on pull requests. The scheduler queues a\n" +
			"nightly reconcile, because GitHub can drop webhooks.\n\n" +
			"Endpoints: POST /webhook and GET /healthz.",
		Example: "  " + envPrefix + "WEBHOOK_SECRET_FILE=/run/secrets/webhook terces serve --listen :8080",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			secret, err := secretValue("WEBHOOK_SECRET", secretFile)
			if err != nil {
				return fmt.Errorf("read webhook secret: %w", err)
			}
			if secret == "" {
				return fmt.Errorf("no webhook secret: set %sWEBHOOK_SECRET or --webhook-secret-file", envPrefix)
			}
			day, ok := weekdays[strings.ToLower(digestDay)]
			if !ok {
				return fmt.Errorf("--digest-day %q is not a weekday", digestDay)
			}
			sw, err := a.pipeline(ctx, true)
			if err != nil {
				return err
			}
			if err := sw.Store.CheckSchema(ctx); err != nil {
				return err
			}

			mux := http.NewServeMux()
			mux.Handle("POST /webhook", &webhook.Handler{Secret: []byte(secret), Queue: sw.Store, Log: a.log})
			mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
				if err := sw.Store.Ping(r.Context()); err != nil {
					http.Error(w, "database unavailable", http.StatusServiceUnavailable)
					return
				}
				fmt.Fprintln(w, "ok")
			})
			srv := &http.Server{
				Addr:              listen,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       60 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    64 << 10,
			}

			var wg sync.WaitGroup
			if !noWorker {
				worker := &webhook.Worker{Store: sw.Store, Pipeline: sw, Log: a.log, Concurrency: jobWorkers}
				sched := &webhook.Scheduler{
					Store: sw.Store, Log: a.log,
					ReconcileHour: reconcileHour,
					DigestWeekday: day, DigestHour: digestHour, Digest: sw.Slack != nil,
				}
				wg.Add(2)
				go func() { defer wg.Done(); worker.Run(ctx) }()
				go func() { defer wg.Done(); sched.Run(ctx) }()
			}

			errCh := make(chan error, 1)
			go func() {
				a.log.Info("listening", "addr", listen, "workers", !noWorker)
				errCh <- srv.ListenAndServe()
			}()
			select {
			case err = <-errCh:
			case <-ctx.Done():
				a.log.Info("shutting down")
				shutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				err = srv.Shutdown(shutCtx)
				cancel()
			}
			wg.Wait()
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringVar(&listen, "listen", env("LISTEN", ":8080"), "listen address (env "+envPrefix+"LISTEN)")
	cmd.Flags().StringVar(&secretFile, "webhook-secret-file", env("WEBHOOK_SECRET_FILE", ""), "file with the webhook secret. "+envPrefix+"WEBHOOK_SECRET sets the secret directly")
	cmd.Flags().IntVar(&jobWorkers, "job-workers", int(envInt("JOB_WORKERS", 2)), "number of jobs that run at the same time (env "+envPrefix+"JOB_WORKERS)")
	cmd.Flags().IntVar(&reconcileHour, "reconcile-hour", int(envInt("RECONCILE_HOUR", 2)), "UTC hour of the nightly sync and scan (env "+envPrefix+"RECONCILE_HOUR)")
	cmd.Flags().StringVar(&digestDay, "digest-day", env("DIGEST_DAY", "monday"), "weekday of the Slack digest (env "+envPrefix+"DIGEST_DAY)")
	cmd.Flags().IntVar(&digestHour, "digest-hour", int(envInt("DIGEST_HOUR", 8)), "UTC hour of the Slack digest (env "+envPrefix+"DIGEST_HOUR)")
	cmd.Flags().BoolVar(&noWorker, "no-worker", false, "run only the webhook listener. Run the workers in another process")
	return cmd
}
