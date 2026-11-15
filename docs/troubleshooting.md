# Troubleshooting

Each entry starts with the message or the symptom, then gives the cause and the fix.

## `no database: set TERCES_DATABASE_URL or --database-url`

The command stores or reads findings, so it needs Postgres. Set the URL:

```bash
export TERCES_DATABASE_URL='postgres://terces_analyst@db.internal:5432/terces?sslmode=verify-full'
```

Local scans such as `scan path` and `scan history` do not need it.

## `<org>/<repo>: not found. Run terces sync first`

The database has no row for the repository. Run a sync, then scan again:

```bash
terces sync --org my-org
terces scan repo my-org/my-repo
```

## The fingerprints change on each run

The CLI has no HMAC key, so it makes a random key for each run. Set the server key:

```bash
export TERCES_HMAC_KEY_FILE=/etc/terces/hmac-key
```

## The pre-commit hook blocks a commit with `terces is not installed`

The hook blocks the commit when it cannot scan. Install the binary on the `PATH`:

```bash
go install ./cmd/terces
```

## `warning: N blobs not scanned in full`

The scan found gaps. See [Local scans: Gaps and warnings](local-scans.md#gaps-and-warnings). To scan larger blobs, raise the limit:

```bash
terces scan history --git-dir my-repo.git --max-blob-size 20971520
```

## `warning: .terces.yaml: invalid YAML at line 3. The scan ignores the file`

The repository allowlist has a syntax error. The scan ran without the allowlist, so it can report findings that the file ignores. Fix the file at the line in the message.

## `sync failed for all N installations`

Every installation failed. The log has one `sync installation failed` line for each, with the cause. Common causes:

- The app private key or the app ID is wrong.
- The org has an IP allow list. Add the egress address of the host to the allow list, or allow GitHub Apps in the org settings.
- The host cannot reach `api.github.com`.

When only some installations fail, the sync continues. The summary counts the failures in `installation_errors`.

## `fetch of <repo> took longer than 1h0m0s`

The fetch hit the time limit. For a large repository, raise the limit:

```bash
terces sync --fetch-timeout 3h
```

When the transfer is slow for all repositories, check the network path to GitHub.

## The pull request check stays at `in_progress`

The worker stopped during the scan. The scheduler requeues the job after 10 minutes without a heartbeat. Check the service log:

```bash
journalctl -u terces --since "1 hour ago"
```

## The pull request check fails, but the secret is a false positive

1. Run `terces findings resolve <fingerprint> --state false_positive --note "<reason>"`.
2. Push a new commit or re-run the check. A resolved secret does not fail the check.

## The HTML report shows no data

The page needs JavaScript. Open the file in a browser with JavaScript on. The page loads nothing from the network, so it works offline.

## `--format sarif needs one repository`

`scan org` does not write SARIF. Scan each repository:

```bash
terces scan repo my-org/my-repo --format sarif > my-repo.sarif
```
