<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="site/assets/brand/terces-wordmark-dark.svg">
    <img alt="terces" src="site/assets/brand/terces-wordmark.svg" width="300">
  </picture>
</p>

terces finds secrets in git repositories. It scans the full history of every repository in your GitHub organizations, blocks new secrets in pull requests and keeps one deduplicated list of findings in Postgres.

It never stores, prints or sends a full secret, and it never tests whether a key is live.

Website: https://bjarneo.github.io/terces/

## Quick start

Install the binary for macOS or Linux. The script checks the archive against `SHA256SUMS` and installs to `/usr/local/bin`. It asks for `sudo` only when that directory is not writable:

```bash
curl -sSfL https://bjarneo.github.io/terces/install.sh | sh
```

To download an archive by hand, see [Getting started](docs/getting-started.md#install-a-release) or the [releases](https://github.com/bjarneo/terces/releases).

Scan a directory:

```bash
terces scan path .
```

Scan the full history of a repository, and get a report:

```bash
git clone --mirror https://github.com/my-org/my-repo.git
terces scan history --git-dir my-repo.git --format html > report.html
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

- git 2.38 or later.
- Go 1.25 or later, only to build from source with `make build`.
- Postgres 15 or later for the server. Local scans do not need it.

## Third-party rules

`rules/gitleaks.yaml` is a conversion of the gitleaks default config, under the MIT license. See `rules/THIRD_PARTY.md`.
