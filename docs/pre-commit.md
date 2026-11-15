# Pre-commit hook

The hook blocks a commit when the staged changes add a secret. It runs on the developer machine, before the secret reaches a remote.

## Install

Use one of these methods.

### With a hooks directory

```bash
go install ./cmd/terces
git config core.hooksPath /path/to/terces/hooks
```

`core.hooksPath` replaces the `.git/hooks` directory of the repository. If the repository has other hooks, copy `hooks/pre-commit` into `.git/hooks/` instead.

### With the pre-commit framework

Add this to `.pre-commit-config.yaml` in the repository:

```yaml
repos:
  - repo: https://git.example.com/security/terces
    rev: v0.1.0
    hooks:
      - id: terces
```

Then run:

```bash
pre-commit install
```

| Hook ID | What it uses |
|---|---|
| `terces` | pre-commit builds terces from the hook repository. It needs Go. |
| `terces-system` | The `terces` binary on the `PATH`. |

## What the hook checks

The hook runs `terces scan --staged`. It reports only secrets that are new in the staged changes.

- An edit to a file with a known secret does not block the commit. The secret is already on the old side of the change.
- A secret that you move to another file is not new either.
- The hook stays silent when the staged changes are clean.

The hook also blocks the commit when terces is not installed or fails. A hook that passes without a scan gives no protection.

## When the hook blocks a commit

1. Remove the secret from the file.
2. Stage the file again with `git add`.
3. If you pushed the secret before, revoke it at its provider. Removal from the file does not make it safe.
4. Commit again.

If you check a finding and it is a false positive, commit with:

```bash
git commit --no-verify
```

To ignore the finding for all developers, add its fingerprint to `.terces.yaml`. See [Repository allowlist](rules.md#repository-allowlist). The allowlist works on a developer machine only with the server HMAC key in `TERCES_HMAC_KEY_FILE`. Without the key, the fingerprints are valid for one run only.

## The hook is not push protection

A developer can skip the hook with `--no-verify` or by not installing it. Use the hook together with a required pull request check. See [Server setup](server-setup.md#7-require-the-check).
