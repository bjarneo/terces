# Output formats

Each format holds previews and fingerprints only. No format holds a full secret.

| Format | Flag | Use it for |
|---|---|---|
| Text | `--format text` | The terminal. This is the default. |
| JSON | `--format json` or `--json` | Scripts and other tools. |
| Markdown | `--format markdown` | Pull request comments, issues in a private tracker and wiki pages. |
| HTML | `--format html` | A report that people open in a browser. |
| SARIF | `--format sarif` | GitHub code scanning and other SARIF tools. |
| CSV | `--format csv` or `--csv` | Spreadsheets. Only `report` supports it. |

Add `--summary` to a scan command to get only the summary. The summary has the counts by severity, the number of different secrets, the top rules and the top repositories.

| Command | Formats | `--summary` |
|---|---|---|
| `scan` and its subcommands | text, json, markdown, html, sarif | yes |
| `findings list` | text, json, markdown, html | no |
| `findings show` | text, json, markdown | no |
| `report` | text, json, csv, markdown, html | no |

`scan org` does not support SARIF. A SARIF file for GitHub holds the results of one repository, so use `scan repo` for each repository.

## Text

```bash
terces scan path .
```

The table goes to stdout. The summary, the gaps, the warnings and the scan statistics go to stderr. A pipe therefore gets the table only.

terces escapes control characters in each value. A file name with a terminal escape sequence shows as a quoted string, such as `"a\x1b[2Kb.env"`, so it cannot hide a row or change your terminal.

## JSON

```bash
terces scan path . --format json | jq '.summary'
```

A scan of a directory, a range, the history or the staged changes writes one object. This example is shortened:

```json
{
  "findings": [
    {
      "fingerprint": "1a44cfc838bc…",
      "rule": "github-pat",
      "severity": "high",
      "preview": "ghp_… (40)",
      "path": "config/app.env",
      "line": 1
    }
  ],
  "summary": { "findings": 1, "secrets": 1, "by_severity": { "high": 1 }, "by_rule": [ { "name": "github-pat", "count": 1 } ], "gaps": 0 },
  "stats": { "blobs_listed": 4, "blobs_scanned": 4, "capped": 0, "duration_ns": 2000000 }
}
```

`scan repo` and `scan org` write `{"summary": …, "repositories": [ … ]}`, with one entry for each repository. With `--summary`, the `findings` arrays are empty.

## Markdown

```bash
terces scan range origin/main..HEAD --format markdown > terces.md
```

The report has a heading, the summary, one table of findings and the gaps. Each value from the repository is in a code span, so a Markdown renderer shows it as text. A file name cannot add a link or HTML to the report.

To post the report on a pull request with the GitHub CLI, run:

```bash
gh pr comment 123 --body-file terces.md
```

Check who can read the pull request before you post. The report names files and shows previews.

## HTML

```bash
terces scan history --git-dir my-repo.git --format html > report.html
```

The report is one file with inline CSS and JavaScript. It loads nothing from the network. A Content-Security-Policy in the page blocks all external requests.

The page has:

- Cards with the counts by severity, the findings and the different secrets.
- Bars for the top rules and the top repositories.
- A table with a text filter, severity buttons and sortable columns.
- The gaps and the warnings of the scan.

The page follows the light or dark mode of the browser. The data goes into the page as escaped JSON, and the script writes it with `textContent` only. A hostile file name cannot add markup or script to the page.

The title of a `scan path` report names the scanned directory, not its full path. A shared report then does not show the home directory of the person who ran it.

## SARIF

```bash
terces scan path . --format sarif > terces.sarif
```

The file is SARIF 2.1.0 with one run. GitHub code scanning reads it.

- Each rule has a `security-severity` score. GitHub shows `critical` as critical, `high` as high, `medium` as medium and `low` as low.
- Each result has the path, the line, the rule and the preview. A result from the history also has the commit in `properties.commit`.
- With the server HMAC key, each result has a partial fingerprint, so GitHub keeps one alert for one secret across scans. Without the key, the fingerprints change on each run. terces then leaves them out, and GitHub computes its own.

To upload the file in GitHub Actions, use the upload action of CodeQL:

```yaml
name: terces
on: [push]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go install ./cmd/terces   # or download your release binary
      - run: terces scan path . --format sarif > terces.sarif || test $? -eq 1
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: terces.sarif
          category: terces
```

`|| test $? -eq 1` keeps the job green when the scan finds secrets, so the upload step runs. The alerts then show in the Security tab.

Before you upload, check who can see code scanning alerts in the repository. Code scanning on a private repository needs GitHub Code Security.

## Summary

```bash
terces scan history --git-dir my-repo.git --summary
terces scan history --git-dir my-repo.git --summary --format markdown
terces scan history --git-dir my-repo.git --summary --format html > summary.html
```

Example text summary:

```text
Summary: 5 findings, 5 different secrets.
  Severity: 1 critical, 3 high, 1 medium, 0 low.
  Top rules:
    aws-access-key-id      1
    aws-secret-access-key  1
    generic-api-key        1
    github-pat             1
    slack-bot-token        1
```

A text scan without `--summary` also writes the summary to stderr, after the table.

## Exit codes

The format does not change the exit code. `0` means no findings, `1` means findings and `2` means an error.
