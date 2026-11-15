# terces

A self-hosted secret scanner for GitHub repositories across multiple organizations. It runs entirely outside GitHub's own secret scanning: you own the engine, the rules and the findings.

> `terces` is a working name. Rename freely.

This README is a **build guide**: what to build, in what order, and the decisions behind it.

---

## Goals and non-goals

**Goals**
- Scan full git history of every repo in every org we own, including PR refs and wikis.
- Keep scanning continuously as new commits arrive.
- Block new leaks at the PR stage and locally before commit.
- One deduplicated view of findings across all orgs.

**Non-goals**
- **No validity checks.** The tool never sends a discovered secret anywhere: no provider API calls, no "is this key live?" tests. A finding is treated as compromised until a human confirms otherwise. Enforce this at the network layer (see [Security](#security)).
- No automatic history rewriting. Revocation is the fix, not `git filter-repo`.
- No server-side push blocking. This isn't possible on github.com (see [Limitations](#limitations)).

---

## Architecture

```
            ┌──────────────┐   webhooks (push, pull_request, installation)
 GitHub ───►│  serve       │──────────────┐
  App       └──────────────┘              ▼
   │                                ┌───────────┐
   │ installation tokens            │ job queue │
   ▼                                └─────┬─────┘
┌──────────┐   git fetch   ┌──────────────┐  │
│  sync    │──────────────►│ mirror store │◄─┘
└──────────┘               └──────┬───────┘
                                  │ unique blobs
                                  ▼
                           ┌──────────────┐     ┌────────────┐
                           │ scan engine  │────►│  Postgres  │──► Slack / reports
                           │ (rules)      │     │  findings  │
                           └──────────────┘     └────────────┘
```

All of this ships as one Go binary with subcommands. The same binary runs as a CLI, a pre-commit hook and a webhook service.

---

## Prerequisites

- Go 1.23+
- git 2.38+ on the scanning host
- Postgres 15+
- Admin rights in each GitHub org (to install the app)
- Optional: Vectorscan/Hyperscan, if regex throughput becomes the bottleneck

---

## Step 1: Create the GitHub App

Create **one** app (Settings → Developer settings → GitHub Apps) and install it in every org.

**Repository permissions**

| Permission | Access | Why |
|---|---|---|
| Contents | Read | Clone and fetch |
| Metadata | Read | List repos |
| Pull requests | Read | PR ranges |
| Checks | Read & write | Report results on PRs |
| Issues | Read | Phase 3: scan issue/PR comments |

**Webhook events:** `push`, `pull_request`, `installation`, `installation_repositories`, `repository`

**Auth flow**
1. Sign a JWT with the app's private key (10-minute expiry).
2. `GET /app/installations` lists one installation per org.
3. `POST /app/installations/{id}/access_tokens` returns a token valid for 1 hour, with its own rate limit.
4. `GET /installation/repositories` lists the repos that installation can see.

Recommended library: `github.com/bradleyfitz/ghinstallation` or `github.com/google/go-github` plus your own JWT code.

**Don't embed tokens in remote URLs.** They get persisted in `.git/config`. Pass them through `GIT_ASKPASS` or `-c http.extraHeader=...` per command.

---

## Step 2: Mirror repositories (`sync`)

```bash
git clone --mirror https://github.com/<org>/<repo>.git  /data/mirrors/<org>/<repo>.git
git -C /data/mirrors/<org>/<repo>.git fetch --prune     # subsequent runs
```

- `--mirror` fetches `+refs/*:refs/*`, which includes GitHub's `refs/pull/*/head`, so PR branches from forks come for free.
- Also try `<repo>.wiki.git`. A failure just means there's no wiki.
- Save each repo's ref tips after every scan in `repos.last_scanned_tips`. These make incremental scans possible.
- Handle renames and transfers by keying repos on GitHub's numeric `repo.id`, not the name.
- Handle archived and deleted repos: keep their findings, stop fetching.

---

## Step 3: Enumerate unique blobs

The key performance idea: **scan blobs, not commits.** Most history shares blobs, so each unique blob gets scanned exactly once.

```bash
# Full scan: every reachable blob with a path
git rev-list --all --objects

# Incremental: only objects new since the last scan
git rev-list --objects --all --not <tip1> <tip2> ...
```

Pipe the object IDs into `git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)'`. Keep only `blob` objects, then read their contents with `git cat-file --batch`.

**Skip:**
- Blobs larger than a limit (start at 5 MB)
- Binary files (a NUL byte in the first 8 KB)
- Paths like `vendor/`, `node_modules/`, `*.min.js`, lockfiles, images and fonts

**Global dedupe:** keep a `scanned_blobs(sha, rules_version)` table. The same blob SHA in a fork or another org is skipped. Bump `rules_version` when the rules change, and everything gets rescanned.

**Attribute lazily.** Only for blobs that have a finding, run:

```bash
git log --all --find-object=<blob_sha> --format='%H %an %ae %aI' --reverse
```

The first line gives the commit that introduced the secret. This is far cheaper than attributing every blob.

---

## Step 4: Detection engine

### Rule format

```yaml
# rules/aws.yaml
- id: aws-access-key-id
  description: AWS access key ID
  keywords: [AKIA, ASIA]               # prefilter, case-insensitive
  regex: '\b((?:AKIA|ASIA)[0-9A-Z]{16})\b'
  secret_group: 1
  severity: high

- id: aws-secret-access-key
  description: AWS secret access key
  keywords: [aws_secret, secret_access_key]
  regex: '(?i)aws.{0,20}secret.{0,20}[=:]\s*["'']?([A-Za-z0-9/+=]{40})'
  secret_group: 1
  entropy_min: 4.0
  pair_with: aws-access-key-id          # only alert if both appear in the same blob
  severity: critical

- id: generic-private-key
  keywords: ["-----BEGIN"]
  regex: '-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----'
  severity: critical
```

### Pipeline for each blob

1. **Keyword prefilter.** Build an Aho-Corasick automaton over all rule keywords (`github.com/cloudflare/ahocorasick` or `github.com/petar-dambovaliev/aho-corasick`). One pass over the blob shows which rules can possibly match. Most blobs match nothing and stop here.
2. **Regex**, run only for the candidate rules. Go's `regexp` (RE2) gives linear time and no catastrophic backtracking. Switch to Vectorscan only if profiling says so.
3. **Entropy filter.** Compute Shannon entropy of the captured secret, and drop matches below `entropy_min`. This kills `password=changeme` noise.
4. **Pairing.** Rules with `pair_with` only report when their partner also matched in the same blob.
5. **Decoding.** Also scan base64-looking runs longer than 40 characters after decoding, and URL-encoded strings. Cap the decode depth at 1.
6. **Allowlists:**
   - Global: known test values (`AKIAIOSFODNN7EXAMPLE`), placeholder strings (`xxxx`, `<your-key>`, `${...}`)
   - Per path: `test/fixtures/**` downgrades severity instead of suppressing
   - Per repo: a `.terces.yaml` in the repo listing **fingerprints** to ignore, never raw values

### Seeding the rules

Don't write 200 rules by hand. Import [gitleaks](https://github.com/gitleaks/gitleaks)' `config/gitleaks.toml` (MIT license; keep the notice in `rules/THIRD_PARTY.md`) with a small converter script. Then tune it against your own repos. Expect to spend most of your time on false positives, not the engine.

Avoid copying from TruffleHog: it's AGPL-3.0.

---

## Step 5: Findings store

**Never store the plaintext secret.**

- `fingerprint = HMAC-SHA256(server_key, secret)`. The key lives in a KMS or secret manager, not in the database.
- `preview = first 4 chars + "…" + length`, e.g. `AKIA… (20)`.

```sql
create table repos (
  id              bigint primary key,      -- GitHub repo.id
  org             text not null,
  name            text not null,
  archived        boolean default false,
  last_scanned_tips jsonb,
  last_scanned_at timestamptz
);

create table secrets (
  fingerprint     bytea primary key,       -- HMAC, dedupes across repos and orgs
  rule_id         text not null,
  preview         text not null,
  severity        text not null,
  state           text not null default 'open',  -- open | revoked | false_positive | ignored
  first_seen_at   timestamptz not null,
  resolved_by     text,
  resolved_note   text
);

create table locations (
  fingerprint     bytea references secrets,
  repo_id         bigint references repos,
  blob_sha        text not null,
  path            text not null,
  line            int,
  commit_sha      text,                    -- introducing commit (lazy)
  author_email    text,
  committed_at    timestamptz,
  primary key (fingerprint, repo_id, blob_sha, path)
);

create table scanned_blobs (
  sha             text primary key,
  rules_version   int not null
);
```

One leaked key copied into 6 repos is **one** `secrets` row with 6 `locations`. That one row is what gets revoked.

---

## Step 6: CLI

```
terces sync                         # discover installations and repos, update mirrors
terces scan org <org>               # scan all mirrored repos in an org
terces scan repo <org>/<repo>       # one repo, full history
terces scan path <dir>              # a local directory (no git)
terces scan --staged                # pre-commit: staged changes only
terces scan range <base>..<head>    # a commit range (used for PRs)

terces findings list [--org] [--state open] [--severity critical]
terces findings show <fingerprint-prefix>
terces findings resolve <fp> --state revoked --note "rotated in AWS console"

terces report [--json | --csv]      # open findings by org, repo, rule, age
terces rules test <rule-id> <file>  # rule development against fixtures
terces serve                        # webhook listener + worker pool
```

**Conventions**
- `--json` on every read command
- Exit codes: `0` clean, `1` findings, `2` error. Hooks and CI depend on these.
- Output never contains a full secret, only preview, path, line and rule.
- Library: `github.com/spf13/cobra`

---

## Step 7: Continuous mode (`serve`)

| Event | Action |
|---|---|
| `installation`, `installation_repositories` | Add or remove repos, trigger a `sync` |
| `push` | Fetch that mirror, run an incremental scan from the stored tips |
| `pull_request` (opened, synchronize) | Scan `base..head`, post a **check run** |
| `repository` (renamed, transferred, archived) | Update metadata |

- Verify `X-Hub-Signature-256` on every webhook.
- Push work onto a queue (Postgres `SKIP LOCKED` is enough at first) and return `200` fast.
- Run a nightly full reconcile with `sync` plus incremental scans of everything. Webhooks get dropped.

**PR check run:** set it to `failure` with annotations (path, line, rule, preview) when there are new findings, and make it required in an org-level ruleset. That's your push protection.

**Pre-commit hook:** use the same binary. Distribute it via [pre-commit](https://pre-commit.com) or a `core.hooksPath` script:

```bash
terces scan --staged || { echo "Secret detected. Commit blocked."; exit 1; }
```

---

## Step 8: Notifications

- Send new `critical`/`high` findings to Slack with org, repo, path, rule, preview, author and a link to the commit.
- Route owners via `CODEOWNERS` when present, otherwise to the commit author.
- Send a weekly digest of open findings by age. Old open findings are the real risk.
- **Don't** open GitHub issues for findings. Issues are visible to everyone with repo access, and on public repos to everyone.

---

## Security

The scanner holds the mirrors of every repo you own and knows where every secret is. Treat it as a crown-jewel system.

- **Egress allowlist:** the host may only reach `github.com`, `api.github.com`, Postgres, Slack and the KMS. This makes the "never test keys" rule enforceable, not just a convention.
- Encrypt the mirror store at rest, and restrict filesystem access to the service account.
- Use least-privilege database roles: the scanner writes, the CLI user reads and resolves.
- Keep an audit log of every `findings show` and `resolve`.
- Keep the GitHub App private key in a KMS or secret manager and rotate it.
- Never log blob contents or matched values, including at debug level.

---

## Limitations

- **No server-side push blocking on github.com.** Pre-receive hooks exist only on GitHub Enterprise Server. A direct push to an unprotected branch still lands. You'll catch it seconds later via the `push` webhook, but by then it's exposed. Mitigate with rulesets that require PRs, plus the pre-commit hook.
- **Force-pushed-away commits** may persist on GitHub (they're reachable by SHA and via PR refs) even after they disappear from your mirror's branches. Keep mirrors append-only: don't `--prune` the `refs/pull/*` refs.
- **Forks outside your orgs** are invisible to the app.
- **Regex detection has limits.** Unstructured passwords and custom internal token formats need custom rules.

---

## Testing

- Unit-test each rule with positive and negative fixtures under `rules/testdata/`.
- **Generate fake secrets at test time**, e.g. `"AKIA" + randomUpper(16)`. Don't commit them. Committed fake tokens will trip GitHub's own push protection and every other scanner that looks at this repo.
- Benchmark on your largest repo: track blobs per second and the prefilter hit rate.
- Measure false positives on real repos before turning on Slack alerts.

---

## Suggested layout

```
cmd/terces/        main.go, cobra commands
internal/githubapp/        JWT, installation tokens, repo discovery
internal/mirror/           clone/fetch, ref tips, blob enumeration
internal/engine/           prefilter, regex, entropy, pairing, decoding, allowlists
internal/rules/            YAML loading, versioning, gitleaks converter
internal/store/            Postgres access, migrations
internal/webhook/          handlers, signature verification, queue
internal/notify/           Slack, digests
rules/                     *.yaml, THIRD_PARTY.md, testdata/
migrations/
```

---

## Roadmap

**Phase 1: Baseline**
- [ ] GitHub App + `sync` across all orgs
- [ ] Blob-level full-history scan with imported gitleaks rules
- [ ] Postgres findings store with HMAC fingerprints
- [ ] `findings list / resolve`, `report`

**Phase 2: Prevention**
- [ ] `serve` with push and PR webhooks, incremental scans
- [ ] Required PR check runs via org rulesets
- [ ] Pre-commit hook distribution
- [ ] Slack alerts and weekly digest

**Phase 3: Coverage**
- [ ] Issue and PR comments, PR review comments
- [ ] Custom rules for internal token formats
- [ ] GitHub Actions logs and artifacts
