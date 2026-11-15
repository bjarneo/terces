# terces documentation

terces finds secrets in git repositories. It scans the full history of each repository in your GitHub organizations, and it stores one deduplicated list of findings in Postgres. It never stores, prints or sends a full secret.

## Start here

| Page | Read it to |
|---|---|
| [Getting started](getting-started.md) | Build terces and run your first scan in 2 minutes. |
| [Local scans](local-scans.md) | Scan a directory, a clone, a commit range or the staged changes. Audit a full account or org. |
| [Output formats](output-formats.md) | Get text, JSON, Markdown, HTML, SARIF or a summary. Upload results to GitHub code scanning. |
| [Pre-commit hook](pre-commit.md) | Block a commit that adds a secret. |

## Run the server

| Page | Read it to |
|---|---|
| [Server setup](server-setup.md) | Create the GitHub App, the database and the service. |
| [Service](service.md) | Learn what the service does for each webhook, job and schedule. |
| [Findings](findings.md) | List, show, resolve and report findings. |
| [Configuration](configuration.md) | Look up each flag and environment variable. |

## Reference

| Page | Read it to |
|---|---|
| [Rules](rules.md) | Write, test and import detection rules. Configure allowlists. |
| [How it works](how-it-works.md) | Learn the scan pipeline, the cache and the data model. |
| [Security](security.md) | Learn the threat model and deploy terces safely. |
| [Limitations](limitations.md) | Learn what terces does not do. |
| [Performance](performance.md) | Read benchmark numbers and tune a large installation. |
| [Troubleshooting](troubleshooting.md) | Fix common errors. |
| [Development](development.md) | Run the tests and find your way in the code. |
