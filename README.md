# terces

terces finds secrets in git repositories. It scans the full history of every repository in your GitHub organizations, blocks new secrets in pull requests and keeps one deduplicated list of findings in Postgres.

It never stores, prints or sends a full secret, and it never tests whether a key is live.

## Quick start

```bash
make build
./bin/terces scan path .
```

Scan the full history of a repository, and get a report:

```bash
git clone --mirror https://github.com/my-org/my-repo.git
./bin/terces scan history --git-dir my-repo.git --format html > report.html
```

The exit code is `0` for no findings, `1` for findings and `2` for an error.

## What it does

- Scans each unique blob one time, across all repositories, forks and orgs.
- Runs 222 rules: the gitleaks default set plus its own rules for AWS keys and private keys.
- Writes text, JSON, Markdown, HTML and SARIF, with an optional summary.
- Blocks a commit that adds a secret, with a pre-commit hook.
- Fails a required pull request check when a change adds a secret.
- Sends new high and critical findings to Slack, plus a weekly digest.

## Documentation

| Topic | Page |
|---|---|
| First scan in 2 minutes | [Getting started](docs/getting-started.md) |
| Scan a directory, a clone, a range or an org | [Local scans](docs/local-scans.md) |
| Text, JSON, Markdown, HTML, SARIF and summaries | [Output formats](docs/output-formats.md) |
| Block secrets before a commit | [Pre-commit hook](docs/pre-commit.md) |
| Run the server for your orgs | [Server setup](docs/server-setup.md) |
| Rules and allowlists | [Rules](docs/rules.md) |
| Flags and environment variables | [Configuration](docs/configuration.md) |
| Threat model and safe deployment | [Security](docs/security.md) |

All pages are in [docs/](docs/README.md).

## Requirements

- Go 1.25 or later to build.
- git 2.38 or later.
- Postgres 15 or later for the server. Local scans do not need it.

## Third-party rules

`rules/gitleaks.yaml` is a conversion of the gitleaks default config, under the MIT license. See `rules/THIRD_PARTY.md`.
