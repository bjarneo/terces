# Security

The service holds a mirror of every repository and knows where every secret is. Treat the host as a high-value system.

## What terces never does

- It never stores, prints, logs or sends a full secret. The store keeps an HMAC-SHA256 fingerprint and a preview. The preview of a secret with 16 or more characters is its first 4 characters and its length, such as `ghp_… (40)`. A shorter secret shows 1 character for each 4 characters of length.
- It never tests whether a key is live. A test would send the secret to a third party.
- It never logs blob contents or matched values, also at the debug level.
- It never puts a token in a remote URL, in `.git/config` or in process arguments.
- It never opens a GitHub issue for a finding. Everyone with access to a repository can read its issues.

## Hostile repository content

Any member of an org can push content to a repository. terces treats all repository content as untrusted.

| Threat | Protection |
|---|---|
| A file name or author name with terminal escape sequences | Text output escapes each control character. Markdown puts values in code spans. HTML sets text with `textContent` only, behind a Content-Security-Policy. |
| A path with invalid UTF-8, or a path longer than the Postgres index limit | The store keys locations on a hash of the raw path, and stores a display form of the path. |
| A path with a newline | The history walk reads NUL-separated output. The finding gets the real path. |
| An author name with a control byte | The walk reads each author field as a separate NUL-separated token. The attribution stays correct. |
| A large file with few keywords | Regexes run only near keyword hits. The time is close to linear in the blob size. |
| A minified file with many candidates on one line | A `line` allowlist sees at most 4 KB on each side of a match. |
| A file with thousands of tokens | The match limit counts different secrets only. A blob at the limit is a reported gap. |
| A large or linked `.terces.yaml` | The scanner reads a regular file of 1 MB or less. Errors name the line, never the content. A bad file is ignored, which can only add findings. |
| A pull request that ignores its own secret | The check reads `.terces.yaml` from the base commit. |

## Failure isolation

| Failure | Effect |
|---|---|
| One org blocks the API, for example with an IP allow list | The sync continues with the other orgs and counts the error. |
| A fetch stalls | The fetch fails at the time limit, by default 1 hour, or after 5 minutes below 1 KB/s. git gets SIGTERM first, so it can remove its lock files. |
| A branch tip from the last scan was pruned | The scan leaves out the missing tip and continues. |
| A worker stops during a job | The scheduler requeues the job after 10 minutes without a heartbeat. |
| A Slack post fails | The alert goes to the job queue and a worker sends it later. |

## Deploy safely

- **Egress allowlist.** Let the host reach only `github.com`, `api.github.com`, Postgres, Slack and your secret manager. This also enforces that terces never tests keys.
- **Mirror store.** Encrypt the disk. terces creates the mirrors with mode `0700`. The systemd unit sets `UMask=0077` and `ProtectSystem=strict`.
- **Database roles.** Use `deploy/roles.sql`. The scanner role writes. The analyst role reads and resolves. Neither role can change or delete audit entries.
- **Secrets.** Give the HMAC key, the app private key, the webhook secret and the Slack URL as files from your secret manager. Rotate the app private key on a schedule.
- **HMAC key.** Keep it secret. With the key, a person can test guesses of a secret against a fingerprint.
- **Slack.** Use a private channel. Alerts name files and link to commits.
- **Reports.** HTML, Markdown and SARIF reports name files and show previews. Share them like the findings list.

## Third-party code

`rules/gitleaks.yaml` is a conversion of the gitleaks default config, under the MIT license. The notice is in `rules/THIRD_PARTY.md`. terces contains no code from TruffleHog, which is under AGPL-3.0.

## Report a vulnerability

Report a vulnerability in terces to the security team of your organization. Do not open a public issue.
