# Local scans

These commands need no GitHub App and no database. They read local files and local git repositories only.

| Command | What it scans |
|---|---|
| `terces scan path <dir>` | The files in a directory. It does not use git. |
| `terces scan history --git-dir <repo>` | Every blob that the refs of a repository reach. |
| `terces scan range <base>..<head>` | The blobs that the commits in a range add. |
| `terces scan --staged` | The staged changes of the repository in the current directory. |

All scan commands accept `--format` and `--summary`. See [Output formats](output-formats.md).

## Scan a directory

```bash
terces scan path ./service
```

- The scan skips `.git` directories and the paths in the global allowlist, such as `node_modules/`.
- The scan reads `.terces.yaml` at the root of the directory. It reads the file only when it is a regular file of 1 MB or less. A link, a larger file or an invalid file adds a warning, and the scan ignores the file.
- The scan does not follow links to other files.

## Scan the full history

```bash
git clone --mirror https://github.com/my-org/my-repo.git
terces scan history --git-dir my-repo.git
```

Use a mirror clone. A normal clone does not have the pull request refs, and it can miss branches. The command detects a bare repository from its layout, so the `.git` suffix is optional.

terces reads each blob one time, also when it occurs in many commits. Each finding shows the commit that added the blob first, and its author.

## Scan a commit range

```bash
terces scan range origin/main..HEAD
terces scan range --git-dir /data/mirrors/123/repo.git 4f1c2e..9ab3d0
```

The scan reports only new secrets. A secret that also exists on the base side of the range is not new. The command reads `.terces.yaml` at the base commit, so a change cannot add an ignore entry for its own secret.

Use this command in CI for a pull request:

```bash
git fetch origin main
terces scan range origin/main..HEAD --format markdown > terces.md
```

## Scan the staged changes

```bash
terces scan --staged
```

The pre-commit hook runs this command. It reports only secrets that the staged changes add. See [Pre-commit hook](pre-commit.md).

## Audit an account or an org

To audit all repositories of a GitHub account or an org without the server, mirror each repository and scan it. This loop uses the GitHub CLI `gh`, which uses your own login. Private repositories need the `repo` scope.

```bash
owner=my-org
mkdir -p ~/audit-$owner && cd ~/audit-$owner
gh repo list "$owner" --source --limit 1000 --json name --jq '.[].name' |
while read -r name; do
  gh repo clone "$owner/$name" "$name.git" -- --mirror --quiet
  terces scan history --git-dir "$name.git" --format json > "$name.json"
done
```

`--source` leaves out forks. To also skip large repositories, filter on `diskUsage`, which is in KB:

```bash
gh repo list "$owner" --source --limit 1000 --json name,diskUsage \
  --jq '.[] | select(.diskUsage < 51200) | .name'
```

The clones hold all source code of the owner. Delete them after the audit:

```bash
rm -rf ~/audit-$owner/*.git
```

For an audit that runs every day and stores the findings, use the server. See [Server setup](server-setup.md).

## Fingerprints and the HMAC key

Each finding has a fingerprint. The fingerprint is an HMAC-SHA256 of the secret with a key.

- Without a key, the CLI makes a random key for each run. The fingerprints are then valid for that run only.
- With the server key, the fingerprints match the server. You need them for the [repository allowlist](rules.md#repository-allowlist) and for stable SARIF alerts.

```bash
export TERCES_HMAC_KEY_FILE=/path/to/hmac-key
terces scan path .
```

Treat the HMAC key as a secret. With the key, a person can test guesses of a secret against a fingerprint.

## Gaps and warnings

A scan reports each blob that it did not read in full:

| Reason | Meaning | What to do |
|---|---|---|
| `too_large` | The blob is text and is larger than `--max-blob-size`. The scan did not read it. | Check the file by hand, or scan again with a larger `--max-blob-size`. |
| `match_limit` | One rule found more than 200 different secrets in the blob. The output shows the first 200. | Check the file by hand. It is often a log or a test fixture. |

A large binary blob is not a gap. The scan counts it as binary. Warnings describe problems that did not stop the scan, such as an invalid `.terces.yaml`.
