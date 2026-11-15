# Server setup

The server mirrors every repository that a GitHub App can see, scans each push and each pull request, and keeps the findings in Postgres. This page sets it up in 7 steps.

## Requirements

- A Linux host with git 2.38 or later and an encrypted disk for the mirrors.
- Postgres 15 or later.
- Admin rights in each GitHub org, to install the app.
- A TLS proxy in front of the webhook listener.

## 1. Create the GitHub App

In GitHub, open Settings, Developer settings, GitHub Apps, and create an app. For an org-owned app, open the org settings instead.

Give the app these repository permissions:

| Permission | Access | Use |
|---|---|---|
| Contents | Read | Clone and fetch |
| Metadata | Read | List repositories |
| Pull requests | Read | Pull request ranges |
| Checks | Read and write | Check runs on pull requests |

Subscribe to these events: `push`, `pull_request`, `installation`, `installation_repositories` and `repository`.

Set the webhook URL to `https://<your-host>/webhook` and set a webhook secret. Create a private key and save the PEM file. Then install the app in each org, for all repositories.

## 2. Create the database

Apply the schema with a role that can create tables. Then create the two working roles:

```bash
createdb terces
terces migrate --database-url postgres://owner@db.internal/terces
psql -d terces -f deploy/roles.sql
```

| Role | What it can do |
|---|---|
| `terces_scanner` | Write repositories, findings, the blob cache and jobs. The service uses it. |
| `terces_analyst` | Read findings, change their state and write the audit log. People use it. It cannot delete or rewrite findings. |

Set a password for each role, or use certificate authentication.

## 3. Create the HMAC key

```bash
openssl rand -hex 32 > /etc/terces/hmac-key
chmod 0400 /etc/terces/hmac-key
```

Keep a copy in your secret manager. Do not change the key later. A new key gives every secret a new fingerprint, so the existing findings no longer match, and the next scan reads all blobs again.

## 4. Set the configuration

Put the settings in `/etc/terces/env`. `deploy/env.example` is a template:

```bash
TERCES_DATABASE_URL=postgres://terces_scanner@db.internal:5432/terces?sslmode=verify-full
TERCES_GITHUB_APP_ID=123456
TERCES_MIRROR_DIR=/data/mirrors
TERCES_LISTEN=127.0.0.1:8080
```

Put each secret in its own file: the HMAC key, the app private key, the webhook secret and the Slack webhook URL. terces never reads a secret from a flag, because other users can read the process arguments. See [Configuration](configuration.md).

## 5. Run the first sync and the baseline scan

```bash
terces sync --scan
terces report
```

The first scan reads the full history of each repository. Review the findings and tune the rules before you set a Slack webhook. Otherwise the baseline sends an alert for each old secret.

To keep a copy of the baseline, write a report:

```bash
terces report --format html > baseline.html
```

## 6. Start the service

`deploy/terces.service` is a systemd unit. It runs as the user `terces`, limits file access and gives the secrets to the process as systemd credentials.

```bash
sudo cp bin/terces /usr/local/bin/
sudo cp deploy/terces.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now terces
```

Put a TLS proxy in front of the listener. The endpoints are `POST /webhook` and `GET /healthz`.

To check the service, run:

```bash
curl -fsS http://127.0.0.1:8080/healthz
journalctl -u terces -f
```

## 7. Require the check

The service posts a check run named `terces` on each pull request. In each org, create a ruleset for the default branch:

1. Require a pull request before a merge.
2. Require the status check `terces`.

The required check is the push protection. On github.com, terces cannot block a direct push, so the ruleset must require pull requests.

## Next steps

- Learn what the service does for each event: [Service](service.md).
- Work with the findings: [Findings](findings.md).
- Lock down the host: [Security](security.md).
