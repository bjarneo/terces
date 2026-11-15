# Configuration

Each setting has a flag and an environment variable. A flag wins over the variable.

terces never reads a secret from a flag, because other users on the host can read the process arguments. Give each secret as a variable or as a file. A file is better, for example a systemd credential.

## Global settings

| Variable | Flag | Default | Use |
|---|---|---|---|
| `TERCES_DATABASE_URL` | `--database-url` | | Postgres URL. Local scans do not need it. |
| `TERCES_HMAC_KEY` | | | Fingerprint key in hex or base64, 32 bytes or more. |
| `TERCES_HMAC_KEY_FILE` | `--hmac-key-file` | | File with the fingerprint key. |
| `TERCES_GITHUB_APP_ID` | `--github-app-id` | | App ID or client ID. |
| `TERCES_GITHUB_APP_KEY` | | | App private key in PEM format. |
| `TERCES_GITHUB_APP_KEY_FILE` | `--github-app-key-file` | | File with the app private key. |
| `TERCES_GITHUB_API_URL` | `--github-api-url` | `https://api.github.com` | REST API URL. |
| `TERCES_GITHUB_URL` | `--github-url` | `https://github.com` | Git URL. |
| `TERCES_SLACK_WEBHOOK_URL` | | | Slack incoming webhook. Alerts are off without it. |
| `TERCES_SLACK_WEBHOOK_URL_FILE` | `--slack-webhook-url-file` | | File with the Slack webhook. |
| `TERCES_MIRROR_DIR` | `--mirror-dir` | `/data/mirrors` | Mirror store. |
| `TERCES_RULES_DIR` | `--rules` | built-in | Directory with rule files. |
| `TERCES_MAX_BLOB_SIZE` | `--max-blob-size` | `5242880` | Largest blob to scan, in bytes. A larger text blob is a gap. |
| `TERCES_FETCH_TIMEOUT` | `--fetch-timeout` | `1h` | Time limit for the fetch of one repository, such as `30m`. |
| `TERCES_WORKERS` | `--workers` | CPU count | Parallel scan workers. |
| `TERCES_LOG_LEVEL` | `--log-level` | `info` | `debug`, `info`, `warn` or `error`. |
| `TERCES_ACTOR` | `--actor` | OS user | Name in the audit log. |

## Service settings

These settings apply to `terces serve`.

| Variable | Flag | Default | Use |
|---|---|---|---|
| `TERCES_WEBHOOK_SECRET` | | | Webhook secret. |
| `TERCES_WEBHOOK_SECRET_FILE` | `--webhook-secret-file` | | File with the webhook secret. |
| `TERCES_LISTEN` | `--listen` | `:8080` | Listen address. |
| `TERCES_JOB_WORKERS` | `--job-workers` | `2` | Jobs that run at the same time. |
| `TERCES_RECONCILE_HOUR` | `--reconcile-hour` | `2` | UTC hour of the nightly sync and scan. |
| `TERCES_DIGEST_DAY` | `--digest-day` | `monday` | Weekday of the Slack digest. |
| `TERCES_DIGEST_HOUR` | `--digest-hour` | `8` | UTC hour of the Slack digest. |
| | `--no-worker` | off | Run only the webhook listener. |

## Command settings

| Command | Flag | Use |
|---|---|---|
| `sync` | `--org` | Sync one org only. |
| `sync` | `--scan` | Scan each repository after its fetch. |
| `sync` | `--concurrency` | Repositories to fetch at the same time. The default is 4. |
| `scan repo`, `scan org` | `--full` | Scan the full history, not only the commits after the last scan. |
| `scan` | `--format`, `--json`, `--summary` | See [Output formats](output-formats.md). |
| `scan range`, `scan history` | `--git-dir` | The repository to scan. The default is the current directory. |

## Files

| File | Use |
|---|---|
| `/etc/terces/env` | Environment file of the systemd unit. See `deploy/env.example`. |
| `/etc/terces/hmac-key` | HMAC key. The unit gives it to the process as a credential. |
| `/etc/terces/github-app.pem` | GitHub App private key. |
| `/etc/terces/webhook-secret` | Webhook secret. |
| `/etc/terces/slack-webhook-url` | Slack webhook URL. |
| `.terces.yaml` | Repository allowlist at the root of a repository. See [Rules](rules.md#repository-allowlist). |
