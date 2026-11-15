# Service

`terces serve` runs three parts in one process: the webhook listener, the job workers and the scheduler. This page describes what each part does.

```bash
terces serve --listen 127.0.0.1:8080
```

To run the listener and the workers in separate processes, start one process with `--no-worker` and one or more without it. Run only one worker process for each mirror store. See [Limitations](limitations.md).

## Webhook listener

The listener verifies the `X-Hub-Signature-256` header with the webhook secret. It then queues a job in Postgres and answers `202`. It does no git work in the request.

| Event | Job |
|---|---|
| `installation` created, deleted or unsuspended | Sync the installation and scan its repositories. |
| `installation_repositories` added | Fetch and scan each new repository. |
| `installation_repositories` removed | Mark the repository as removed. Its findings stay. |
| `push` | Fetch the mirror and scan the commits after the last scan. |
| `pull_request` opened, synchronize, reopened or base edited | Scan `base..head`, post a check run, then scan the repository. |
| `repository` renamed, transferred, archived and other actions | Update the metadata. An archived repository gets one last fetch. |

## Job workers

Workers claim jobs with `FOR UPDATE SKIP LOCKED`, so two workers never run the same job.

- A failed job runs again after 2, 4, 8 and 16 minutes. After 5 attempts, it is `failed`.
- A worker sends a heartbeat while a job runs. When a worker stops, the scheduler puts its job back in the queue after 10 minutes without a heartbeat.
- A job that stops the worker 5 times is `failed`.
- The queue keeps one queued job for each repository and kind. A burst of pushes gives one scan, not one scan for each push.

## Scheduler

| Schedule | Job |
|---|---|
| Each night at `--reconcile-hour` UTC | Sync all installations and scan all repositories. GitHub can drop webhooks, so the reconcile catches them. |
| Each week on `--digest-day` at `--digest-hour` UTC | Post the digest of open findings to Slack. Only when Slack is set. |
| Each minute | Requeue stale jobs. Delete finished jobs that are older than 7 days. |

## Sync

A sync lists the installations, then the repositories of each installation, then fetches each mirror.

- A failure in one installation, such as an IP allow list in that org, does not stop the sync of the other installations. The summary counts it in `installation_errors`.
- Each fetch has a time limit, by default 1 hour. A transfer that stays below 1 KB/s for 5 minutes also stops. A stalled fetch then fails and frees its worker.
- An archived repository gets no new fetch after its last one. When the rules version changes, the sync still scans its mirror again.

## Pull request checks

The service scans `base..head` of each pull request and posts a check run named `terces`.

- The check fails when the range adds a secret that is `open` or unknown.
- A secret that a person marked as `revoked`, `false_positive` or `ignored` does not fail the check.
- When the scan fails, the check fails too. A required check never passes without a scan.
- The check reads `.terces.yaml` from the base commit, so a pull request cannot ignore its own secret.
- The check lists each new secret as an annotation with the rule and the preview.

## Slack alerts

When `TERCES_SLACK_WEBHOOK_URL_FILE` is set, the service sends an alert for each new `high` or `critical` secret. The alert names the owners from `CODEOWNERS`, or the commit author. It links to the commit.

When a Slack post fails, the alert goes to the job queue, and a worker sends it later. Errors never contain the webhook URL.

Use a private channel. The alerts name files and show previews.
