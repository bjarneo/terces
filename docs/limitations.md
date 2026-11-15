# Limitations

These are known limits of terces. Each item says what to do instead.

## Detection

- **Regex detection has limits.** Unstructured passwords and internal token formats need custom rules. See [Rules](rules.md#add-a-rule-for-an-internal-token).
- **No validity checks.** terces cannot tell a live key from a revoked one, because it never sends a secret to a provider. Treat each finding as live until a person checks it.
- **Matches longer than the window.** A rule whose regex has a repeat without an upper bound, such as `x+`, counts the repeat as 4 KB. A match with a longer run can go unreported when the run does not reach the edge of the window. Real secrets are much shorter.
- **Blobs above the size limit get no scan.** The scan reports each such text blob as a `too_large` gap. Check the gaps by hand, or raise `--max-blob-size`.
- **Comments and Actions logs are not scanned.** terces scans git content only: branches, tags, pull request refs and wikis. It does not scan issue comments, pull request comments, GitHub Actions logs or artifacts.

## Coverage

- **No server-side push blocking on github.com.** Pre-receive hooks exist only on GitHub Enterprise Server. A direct push to an unprotected branch still lands. The `push` webhook reports it seconds later, but the secret is already exposed. Use rulesets that require pull requests, plus the pre-commit hook.
- **Forks outside your orgs** are invisible to the app.
- **The pre-commit hook is optional.** A developer can skip it with `--no-verify`. The required pull request check is the control that a developer cannot skip.

## Operation

- **One worker process for each mirror store.** The locks that keep two jobs off the same mirror are in the process. Run one `serve` process with workers for each mirror store. Extra listener processes with `--no-worker` are safe.
- **Owner routing.** A Slack alert names the owners from `CODEOWNERS` or the commit author. It does not send a message to each owner.
- **Repository allowlist on developer machines.** The allowlist works only with the server HMAC key. Without the key, the pre-commit hook does not apply `.terces.yaml`.
- **SARIF for one repository.** `scan org` does not write SARIF. Use `scan repo` for each repository.

## Platforms

- The tests run on Linux with git 2.56 and Postgres 17.
- GitHub Enterprise Server is not tested. The API and git URLs are settings, so it can work.
- The binary builds for macOS and Windows, but these platforms are not tested.
