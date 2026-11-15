# Development

## Run the tests

```bash
make test       # tests that do not need Postgres
make db-up      # start a Postgres container on 127.0.0.1:55432
make test-db    # all tests with the race detector, including Postgres and the end-to-end test
make db-down    # stop the container
```

Tests that need Postgres skip when `TERCES_TEST_DATABASE_URL` is not set. Each test gets its own temporary database.

The end-to-end test in `internal/webhook/e2e_test.go` uses a fake GitHub API, git remotes on disk and a real Postgres database. It runs a sync and a scan, sends signed `pull_request` webhooks and checks the check runs. It also checks that no token or secret reaches the logs, the mirror config or Slack.

## Test data

No file in this repository holds a fake secret. Tests generate fake secrets at run time with `internal/testsecret`, from a fixed seed. To change the seed, set `TESTSECRET_SEED`.

The project scans itself without findings:

```bash
make build
./bin/terces scan path .
```

## Layout

```text
cmd/terces/            CLI commands and output
internal/engine/       prefilter, regex windows, entropy, pairing, decoding, allowlists
internal/rules/        rule loading, validation, hashing, gitleaks converter
internal/scanner/      history, range, staged and directory scans, blob cache, gaps
internal/mirror/       git commands, mirror store, blob listing, history walk
internal/pipeline/     sync, repository scans, pull request checks
internal/store/        Postgres queries, job queue
internal/githubapp/    JWT, installation tokens, repositories, check runs
internal/webhook/      webhook handler, worker, scheduler
internal/notify/       Slack alerts, digest, CODEOWNERS
internal/render/       Markdown, HTML, SARIF and summary output
internal/safetext/     escapes for untrusted text
internal/fingerprint/  HMAC fingerprints and previews
internal/repoconfig/   .terces.yaml parser
internal/pathmatch/    gitignore-style globs
rules/                 built-in rules, THIRD_PARTY.md, testdata/
migrations/            SQL schema
deploy/                systemd unit, database roles, example environment
hooks/                 pre-commit hook
docs/                  this documentation
site/                  GitHub Pages site
scripts/               site-examples.sh for the site examples
.github/workflows/     Pages deployment
```

## Release

To publish a release, push a tag that starts with `v`:

```bash
git tag v0.2.0
git push origin v0.2.0
```

`.github/workflows/release.yml` runs the tests, runs `scripts/release.sh` and publishes the archives and `SHA256SUMS` on the release page. To build the same archives locally into `dist/`, run:

```bash
make dist VERSION=v0.2.0
```

## Website

The GitHub Pages site is in `site/`. It is static HTML, CSS and JavaScript with no external requests. `.github/workflows/pages.yml` deploys it on each push to `main` that changes `site/`.

The examples on the page are real terces output from a synthetic repository with fake tokens. To make them again after a change to the output, run:

```bash
make site
```

`scripts/site-examples.sh` creates the repository in a temporary directory, scans it, writes `site/example/report.html`, fills each `<!-- example:NAME -->` block in `site/index.html` and takes the report screenshots when Chromium and ImageMagick exist. It then scans `site/` and fails when it finds a secret.

To view the site locally, run:

```bash
python3 -m http.server 8000 --directory site
```

## Change the engine

Increase `engine.Version` in `internal/engine/engine.go` when a change can change the findings for the same rules. A new version makes each repository scan its full history again.

`TestWindowedScanMatchesFullScan` checks that the regex windows give the same results as a full scan for all built-in rules. Run it after each change to the windows or to the rules:

```bash
go test ./internal/engine -run TestWindowedScanMatchesFullScan
```

## Change the schema

The schema is in `migrations/`. `terces migrate` applies new files in name order, under an advisory lock. Add a new numbered file for each change, such as `0002_add_column.sql`. Do not edit a migration that a database has applied.

## Write prose

Write documentation, comments, error messages and CLI help in ASD-STE100 Simplified Technical English:

- Keep a sentence to 20 words for an instruction and 25 words for a description.
- Use the active voice and the present tense.
- Put commands, paths and code in code formatting.
