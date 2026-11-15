# Rules

A rule finds one kind of secret. terces has 222 built-in rules: 219 converted from the gitleaks default config, plus its own rules for AWS keys and private keys.

```bash
terces rules list
terces rules list --json | jq '.[].id'
```

## Rule files

Each `*.yaml` file in `rules/` holds a list of rules. `rules/allowlist.yaml` holds the global allowlist. The binary contains the files from build time. After you change a rule file, build again with `make build`. To load a directory at run time instead, use `--rules ./rules`.

```yaml
- id: aws-secret-access-key
  description: AWS secret access key
  keywords: [aws]
  regex: '(?i)aws.{0,20}secret.{0,20}[=:]\s*["'']?([A-Za-z0-9/+=]{40})'
  secret_group: 1
  entropy_min: 4.0
  pair_with: aws-access-key-id
  severity: critical
```

| Field | Use |
|---|---|
| `id` | Unique name of the rule. |
| `description` | Text for reports and SARIF. |
| `keywords` | Words for the prefilter. The comparison ignores case. |
| `regex` | Go RE2 syntax. The run time is linear in the input size. |
| `secret_group` | Capture group of the secret. Without it, the engine uses the first non-empty group. A regex without groups uses the full match. |
| `entropy_min` | The engine drops a match with a lower Shannon entropy. |
| `pair_with` | The rule reports only when this other rule matches in the same blob. |
| `severity` | `low`, `medium`, `high` or `critical`. |
| `path` | Regex. The rule applies only to matching paths. |
| `allow` | Allowlist entries for this rule. See [Rule allowlists](#rule-allowlists). |

## Keywords

The regex of a rule runs only when one of its keywords occurs in the blob. For speed, it runs only near each keyword hit.

Follow these rules for keywords:

- Each match of the regex must contain one of the keywords. A match without a keyword can go unreported.
- Use the most specific text, such as `ghp_` or `AKIA`, not `key`.
- Use 3 or more characters. A short keyword selects too many blobs.

The engine checks the regex when it loads the rule:

- When it can prove that each match contains a keyword and that a match has a length limit, it runs the regex in a window around each keyword hit. A repeat such as `x+` counts as 4 KB for the window.
- In all other cases, it runs the regex on the full blob, which is slower but complete.

202 of the 222 built-in rules use windows. The results are the same as for a full scan. A test checks this for all built-in rules.

## Decoding

The engine also decodes base64 runs of 40 or more characters and URL-encoded strings, one level deep. A secret in decoded text reports the line of the encoded text. A plain and an encoded copy of the same secret give one finding.

## Match limit

The engine keeps up to 200 different secrets for one rule in one blob. Copies of a kept secret and matches that a filter drops do not count toward the limit. A blob that reaches the limit is a `match_limit` gap in the scan output.

## Rule allowlists

An `allow` entry drops matches of one rule.

```yaml
  allow:
    - regex_target: line
      regexes: ['# example']
    - condition: and
      regexes: ['^tok_0']
      paths: ['(^|/)examples/']
```

| Field | Use |
|---|---|
| `regexes` | Regexes to test against the target. |
| `stopwords` | Words. A secret that contains one of them is dropped. |
| `paths` | Path regexes. |
| `regex_target` | `secret`, `match` or `line`. The default is `secret`. `line` sees up to 4 KB on each side of the match. |
| `condition` | `or` or `and`. With `and`, all criteria that are set must match. The default is `or`. |

## Global allowlist

`rules/allowlist.yaml` applies to all rules:

| Key | Use |
|---|---|
| `values` | Exact values that are never findings, such as documented example keys. |
| `regexes` | Placeholders such as `xxxx`, `<your-key>` and `${VAR}`. |
| `stopwords` | Words that mark a placeholder. |
| `skip_paths` | Gitignore-style globs that the scanner never reads, such as `node_modules/`, lockfiles, images and fonts. |
| `skip_path_regexes` | Regexes for paths that the scanner never reads. |
| `downgrade_paths` | Globs such as `test/fixtures/`. A finding at such a path gets the severity `low`. |

A blob that the history lists at a skipped path, and that a commit also adds at a normal path, still gets a scan. A secret in both `node_modules/` and `src/` is therefore found.

## Repository allowlist

To ignore a known false positive in one repository, add its fingerprint to `.terces.yaml` at the root of the default branch:

```yaml
ignore:
  - fingerprint: 3f2a9c1b04de5f6a7b8c9d0e1f2a3b4c
    note: fake key in the API docs
  - 9a8b7c6d5e4f3a2b1c0d9e8f
```

- Use 16 or more hex characters of the fingerprint. A shorter prefix can match other secrets.
- The file holds fingerprints only, never raw values.
- The fingerprints depend on the server HMAC key. Get them from `terces findings show`.
- A pull request check and `scan range` read the file from the base commit. An ignore entry applies after it is merged.
- The scanner reads a file of 1 MB or less. A larger or invalid file adds a warning, and the scan ignores the file. This can only add findings.

## Test a rule

`rules test` shows every match of one rule in a file, with the reason for each dropped match:

```bash
terces rules test generic-api-key ./config/app.yaml
```

```text
LINE  PREVIEW     ENTROPY  DECODED  RESULT
1     W1jK… (40)  4.47              finding, severity medium
2     aaaa… (40)  0.00              dropped: entropy 0.00 is below 3.50
2 matches, 1 finding
```

Use it to tune a rule before you add it.

## Test fixtures

The fixtures in `rules/testdata/` are templates. The test expands placeholders such as `{{rand:A-Z2-7:16}}` at run time:

```yaml
- rule: github-pat
  positive:
    - "GITHUB_TOKEN=ghp_{{rand:A-Za-z0-9:36}}"
  negative:
    - "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

No file in this repository holds a fake token. A committed fake token trips GitHub push protection and other scanners. See `rules/testdata/README.md`.

## Update the gitleaks rules

`rules/gitleaks.yaml` is a conversion of the gitleaks default config. To convert a new version, run:

```bash
curl -sSfLo gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
make rules GITLEAKS_TOML=gitleaks.toml
make build
```

The converter leaves out `aws-access-token` and `private-key`, because `aws.yaml` and `private-keys.yaml` cover them. It skips rules that match file paths only. It sets the severity `critical` for private keys, `medium` for generic rules and `high` for all others. The gitleaks license is in `rules/THIRD_PARTY.md`.

## Add a rule for an internal token

1. Create `rules/internal.yaml`:

   ```yaml
   - id: acme-service-token
     description: ACME internal service token
     keywords: [acmetok_]
     regex: '\b(acmetok_[a-z0-9]{32})\b'
     entropy_min: 3.5
     severity: high
   ```

2. Add a fixture in `rules/testdata/internal.yaml`:

   ```yaml
   - rule: acme-service-token
     positive:
       - "TOKEN=acmetok_{{rand:a-z0-9:32}}"
   ```

3. Run the tests and build:

   ```bash
   go test ./rules/
   make build
   ```

## Cache version

The blob cache stores results by cache version. The version is a hash of the rules, the global allowlist, the engine version, the size limit and an ID of the HMAC key. `terces rules list` shows it.

When the version changes, the next scan of each repository covers its full history again and reads all blobs again. A rule change therefore reaches old commits without a manual `--full` scan. This also applies to archived repositories.
