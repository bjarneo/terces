# Findings

The store keeps one finding for each secret. A secret in 3 repositories is one finding with 3 locations. Resolve it one time, after you revoke it.

These commands need the database. Set `TERCES_DATABASE_URL`, and use the `terces_analyst` role.

## List findings

```bash
terces findings list --state open --severity high
terces findings list --org my-org --format json
terces findings list --repo my-org/api --rule github-pat
terces findings list --format html > findings.html
```

| Flag | Effect |
|---|---|
| `--state` | Only one state: `open`, `revoked`, `false_positive` or `ignored`. |
| `--severity` | This severity or a higher one. `high` lists `high` and `critical`. |
| `--org` | Only findings with a location in this org. |
| `--repo` | Only findings with a location in this repository, as `org/repo`. |
| `--rule` | Only one rule. |
| `--limit` | The maximum number of rows. The default is 1000. |

When more findings match than `--limit` allows, the command says so. The JSON output has `"truncated": true`.

## Show one finding

```bash
terces findings show 3f2a9c1b04de
```

Give 6 or more hex characters of the fingerprint. The prefix must match one finding only. The command shows the rule, the preview, the state and every location with its commit and author. Each call writes an entry in the audit log.

## Resolve a finding

```bash
terces findings resolve 3f2a9c1b04de --state revoked --note "rotated in AWS console"
```

| State | Use it when |
|---|---|
| `open` | The secret can still be live. This is the start state. |
| `revoked` | You revoked the secret at its provider. |
| `false_positive` | The match is not a secret. |
| `ignored` | The secret is not a risk, for example a test key with no access. |

`--note` is required for each state except `open`. Each change writes an entry in the audit log, with the actor and the database role. Set the actor with `--actor`. The default is the OS user.

A resolved secret does not fail a pull request check and does not send a new alert.

## Report

```bash
terces report
terces report --org my-org --format csv > open-findings.csv
terces report --format markdown
terces report --format html > open-findings.html
terces report --slack
```

The report groups the open findings by org, repository, rule and severity. It shows the age of the oldest finding in each group. A secret in more than one repository counts one time in each repository.

`report --slack` posts the weekly digest now. Use it from cron when the service does not run.

## Audit log

`findings show` and `findings resolve` write to the `audit_log` table. Each entry has the time, the actor, the database role, the action and the fingerprint. The `terces_analyst` role can add entries but cannot change or delete them.

```sql
select at, actor, db_user, action, encode(fingerprint, 'hex'), detail
from audit_log
order by at desc
limit 20;
```
