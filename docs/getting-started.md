# Getting started

This page takes you from source code to your first scan. You need no GitHub App and no database for these steps.

## Requirements

- Go 1.25 or later to build. The Postgres driver pgx v5.13 needs Go 1.25.
- git 2.38 or later.

## Build

```bash
git clone <your-terces-remote> terces
cd terces
make build
./bin/terces --version
```

The binary is `bin/terces`. It contains the built-in rules. To put it on your `PATH`, run:

```bash
go install ./cmd/terces
```

## Scan a directory

```bash
terces scan path ./my-service
```

terces reads the files below the directory. It does not use git, so it sees the current files only.

Example output:

```text
SEVERITY  RULE                   PREVIEW     LOCATION              FINGERPRINT
critical  aws-secret-access-key  fqgi… (40)  deploy/credentials:2  c02fd4290409
high      github-pat             ghp_… (40)  config/app.env:1      ab7d3d28b190
high      aws-access-key-id      AKIA… (20)  deploy/credentials:1  7915463e9e93

Summary: 3 findings, 3 different secrets.
  Severity: 1 critical, 2 high, 0 medium, 0 low.
  Top rules:
    aws-access-key-id      1
    aws-secret-access-key  1
    github-pat             1
3 findings. 2 blobs listed, 2 scanned, 0 cached, 0 skipped (path 0, size 0, binary 0), 1714 blobs/s, prefilter hit rate 100.0%, 1ms
```

The table goes to stdout. The summary and the statistics go to stderr. Each row is one secret at one location. The preview shows the first characters and the length of the secret. The output never shows a full secret.

## Scan the full history of a repository

Secrets that a later commit deleted are still in the history. To find them, scan a mirror clone:

```bash
git clone --mirror https://github.com/my-org/my-repo.git
terces scan history --git-dir my-repo.git
```

## Read the exit code

| Code | Meaning |
|---|---|
| `0` | The scan found no secrets. |
| `1` | The scan found one or more secrets. |
| `2` | An error stopped the command. |

Use the exit code in scripts and in CI.

## Get a report

```bash
terces scan history --git-dir my-repo.git --format html > report.html
terces scan history --git-dir my-repo.git --summary
```

See [Output formats](output-formats.md) for all formats.

## Act on a finding

1. Treat the secret as compromised. terces cannot tell if a key is live, and it never tests keys.
2. Revoke the secret at its provider, for example in the AWS console.
3. Remove the secret from the code. Use a secret manager instead.
4. If the repository is public or shared widely, consider a history rewrite. A revoked secret is safe in the history.

## Next steps

- Audit all repositories of an account or an org: [Local scans](local-scans.md#audit-an-account-or-an-org).
- Block new secrets on developer machines: [Pre-commit hook](pre-commit.md).
- Scan every push and every pull request: [Server setup](server-setup.md).
