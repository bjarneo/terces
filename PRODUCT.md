# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

The CLI is one Go binary. Its HTML report is one self-contained file with inline CSS and vanilla JavaScript and no external requests. The GitHub Pages site is static HTML, CSS and minimal vanilla JavaScript in `site/`, deployed by a GitHub Actions workflow, with no external resources. The user asked for vanilla HTML, CSS and JS for the report. The site follows the same stack.

## Users

- Platform and security engineers in organizations on GitHub who must find and stop leaked credentials across hundreds of repositories, and who prefer to self-host the scanner.
- Developers in those organizations who meet terces as a pre-commit hook or as a failed pull request check.
- The project is public open source. The site is for people who evaluate whether to adopt and self-host terces.

## Product Purpose

terces finds secrets in git repositories. It scans the full history of every repository in the GitHub organizations where its GitHub App is installed, blocks new secrets in pull requests through a required check, blocks them on developer machines through a pre-commit hook, and keeps one deduplicated list of findings in Postgres. Success means every leaked credential is found, revoked and tracked, without the scanner itself becoming a new place where secrets leak.

## Positioning

- Self-hosted: one Go binary, your own Postgres, your own mirrors. No SaaS.
- It never stores, prints, logs or sends a full secret. Findings hold an HMAC-SHA256 fingerprint and a short preview, such as `ghp_… (40)`.
- It never tests whether a key is live, so it never sends a secret to a third party.
- It reads each unique blob one time across all repositories, forks and orgs, and caches the result by blob SHA.
- It treats repository content as hostile: file names, author names and config files from a repository cannot break its output, its store or its terminal.

## Operating Context

- CLI on a laptop: `scan path`, `scan history` on a mirror clone, `scan range` in CI, `scan --staged` in the pre-commit hook.
- Server on a Linux host: `sync`, `serve` with GitHub webhooks, a job queue in Postgres, nightly reconcile, Slack alerts and a weekly digest.
- Output formats: text, JSON, Markdown, HTML, SARIF for GitHub code scanning, CSV for `report`, and a summary mode.
- Exit codes: 0 no findings, 1 findings, 2 error.

## Capabilities and Constraints

- 222 built-in rules: 219 converted from the gitleaks default config under its MIT license, plus own rules for AWS keys and private keys.
- Benchmark, measured on one laptop with 16 threads: full history of the gitleaks repository, 4,026 commits, 10,306 blobs, 46 MB, 6,287 findings in 3.2 s.
- Requirements: Go 1.25 or later to build, git 2.38 or later, Postgres 15 or later for the server only.
- Not supported: server-side push blocking on github.com, issue and pull request comments, GitHub Actions logs, validity checks.
- Phase 3 of the roadmap, comments and Actions logs, is not started.

## Brand Commitments

- Name: `terces`, always lowercase. It is "secret" spelled backward.
- Logo: "Terces Logo 1a" from the user's design project, with the highlighted code line in the site green. The files are in `site/assets/brand/`.
- Repository: `https://github.com/bjarneo/terces`. The user approved this URL for the site links.
- License: MIT. The copyright holder in `LICENSE` is a neutral placeholder.
- Voice: ASD-STE100 Simplified Technical English in a developer-relations voice. Outcome first, short sentences, active voice, no hype, no superlatives, no filler, runnable examples.

## Evidence on Hand

- Real CLI output, real HTML report, Markdown and SARIF output, all produced by the binary from synthetic fake tokens generated at run time. Any example on the site is synthetic and must say so.
- The benchmark above.
- No users, customers, testimonials, stars, download counts or press exist. The site must not invent them.

## Product Principles

- The scanner must never become a new place where a secret leaks.
- Show proof, not claims: real output, measured numbers.
- Self-hosted and transparent: every rule is a YAML file the user can read.
- Fail closed: a check that cannot scan does not pass.

## Accessibility & Inclusion

Pages must work with keyboard and screen reader, follow light and dark mode, and stay readable at phone width.
