# How it works

This page describes the scan pipeline, the cache and the data model. Read it to tune terces or to change the code.

## Components

```text
GitHub ──webhooks──▶ listener ──▶ jobs (Postgres) ──▶ workers
   ▲                                                    │
   └──── API: installations, repositories, checks ◀─────┤
                                                        ▼
                       mirrors on disk ◀── git fetch ── pipeline ──▶ scanner ──▶ engine
                                                        │
                                                        ▼
                                             findings store (Postgres)
```

| Package | Job |
|---|---|
| `internal/githubapp` | JWT, installation tokens, repository lists, check runs. |
| `internal/mirror` | git commands, the mirror store, blob listing and the history walk. |
| `internal/engine` | Prefilter, regex, entropy, pairing, decoding and allowlists on one blob. |
| `internal/scanner` | History, range, staged and directory scans. The blob cache. Gaps. |
| `internal/pipeline` | Sync, repository scans and pull request checks. |
| `internal/store` | Postgres queries and the job queue. |
| `internal/render` | Markdown, HTML and SARIF output, and the summary. |
| `internal/safetext` | Escapes for untrusted text in output and in the database. |

## Scan pipeline

1. **Fetch.** `sync` fetches each mirror. Branches and tags are fetched with `--prune`. `refs/pull/*/head` is fetched without `--prune`, because GitHub keeps closed and force-pushed pull request commits readable by SHA. The token goes to git as an HTTP header in the environment. It never goes into the remote URL, `.git/config` or the process arguments.
2. **List.** The scanner lists blobs with `git rev-list --objects --all`. An incremental scan leaves out the history of the ref tips of the last scan. A tip that no longer exists is left out of the list.
3. **Filter.** The scanner skips blobs at allowlisted paths. A text blob above `--max-blob-size` is a gap. A binary blob gets no scan.
4. **Cache.** The scanner looks up the other blobs in the cache. It reads only the blobs that the cache does not have.
5. **Scan.** For each blob, the engine runs the keyword prefilter, the regexes of the candidate rules near the keyword hits, the entropy filter, the allowlists, the decoder and the pairing check.
6. **Walk.** One `git log --raw --reverse -m -z` walk over the same commits finds all paths and the first commit of each blob with a finding. The walk also finds blobs that the listing missed. See [The history walk](#the-history-walk).
7. **Localize.** The scanner applies the path rules and the repository allowlist to each location. The cache therefore stays valid for the same blob at another path.
8. **Store.** The store records one row for each secret and one row for each location.

## The keyword prefilter

An Aho-Corasick automaton finds all keywords of all rules in one pass over the blob. The comparison ignores ASCII case. A rule whose keyword does not occur gets no regex run.

When a keyword occurs, the regex of the rule runs in a window around each hit, not over the full blob. The window size comes from the longest possible match of the regex. A 3.7 MB JSON file with 18 hits of one keyword then costs 18 small regex runs. See [Rules: Keywords](rules.md#keywords).

## The history walk

`git rev-list` reports each blob at one path only, and an incremental listing leaves out a blob that the old tips already reach. The walk finds these cases:

- All paths and the first commit of each blob with a finding.
- A blob that the listing reported at a skipped path, such as `node_modules/`, but that a commit also adds at a normal path. The scanner reads it.
- In an incremental scan, a blob from older history that a new commit adds at a new path, such as a copy or a revert. The scanner reads it.

The walk reads NUL-separated output only. A path or an author name can hold any byte except NUL, so no other separator is safe. With `-m`, git compares a merge with each parent, so a blob that only a merge resolution adds gets the merge commit.

## The blob cache

The cache stores the content result of each blob by SHA and cache version: the fingerprints, rules, lines and previews. It never stores plaintext. A blob that occurs in a fork or in another org then needs no second read.

The cache version is a hash of the rules, the global allowlist, the engine version, the size limit and an ID of the HMAC key. A new version makes the next scan of each repository read its full history again.

The cache also keeps the match-limit flag of each blob, so a later scan reports the same gap. A blob above the size limit is not in the cache. Each scan checks its size again and reports it again.

## Gaps

A gap is a blob that the scan did not read in full. The scan output lists up to 100 gaps and counts all of them.

| Reason | Cause |
|---|---|
| `too_large` | A text blob above `--max-blob-size`. |
| `match_limit` | A rule found more than 200 different secrets in the blob. |

## Data model

| Table | Content |
|---|---|
| `repos` | One row for each repository, keyed on the GitHub repository ID. A rename keeps the row. |
| `secrets` | One row for each secret, keyed on the HMAC fingerprint. It holds the rule, the preview, the severity and the state. |
| `locations` | One row for each place of a secret: repository, blob, path, line, commit and author email. |
| `scanned_blobs` | The blobs that a cache version has read, with the match-limit flag. |
| `blob_findings` | The content results of each scanned blob. |
| `audit_log` | Each `findings show` and `findings resolve`, with the actor and the database role. |
| `jobs` | The job queue of the service. |

`locations` keys each row on a SHA-256 hash of the raw path. The `path` column holds a display form: a path with invalid UTF-8 or a control byte is a quoted Go string. A hostile path then cannot fail the transaction that holds all findings of a repository.

## Mirror store

```text
<mirror-dir>/<repo-id>/repo.git
<mirror-dir>/<repo-id>/wiki.git
```

The store keys each repository on its numeric GitHub ID, so a rename or a transfer keeps the mirror. The first fetch goes to a temporary directory and then moves into place, so an interrupted fetch leaves no half-filled mirror. A repository that the app can no longer see keeps its findings, but sync stops fetching it.
