#!/usr/bin/env bash
# site-examples.sh writes the examples of the GitHub Pages site.
#
# It creates a synthetic repository with fake tokens in a temporary
# directory, scans it with bin/terces, and writes:
#   - site/example/report.html, the interactive example report
#   - each <!-- example:NAME --> block in site/index.html
#
# The fake tokens exist only in the temporary directory. The site holds
# previews and fingerprints only, never a full token.
#
# Usage: make build && scripts/site-examples.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/bin/terces"
test -x "$bin" || { echo "build first: make build" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export TERCES_HMAC_KEY_FILE="$work/hmac-key"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TERCES_HMAC_KEY_FILE"

rnd() { LC_ALL=C tr -dc "$1" < /dev/urandom | head -c "$2"; }
commit() {
	GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" GIT_COMMITTER_NAME="$1" GIT_COMMITTER_EMAIL="$2" \
		GIT_AUTHOR_DATE="$3" GIT_COMMITTER_DATE="$3" git -C "$repo" commit -q -m "$4"
}

repo="$work/acme-payments"
git init -q -b main "$repo"
mkdir -p "$repo/src" "$repo/deploy" "$repo/config"
printf '# acme-payments\n\nPayment API for the Acme store.\n' > "$repo/README.md"
printf 'package main\n\nfunc main() {}\n' > "$repo/main.go"
git -C "$repo" add -A
commit "Dana Example" dana@example.com 2026-03-02T09:14:00Z "Add service skeleton"
printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' "$(rnd A-Z2-7 16)" "$(rnd A-Za-z0-9 40)" > "$repo/deploy/credentials"
git -C "$repo" add -A
commit "Sam Example" sam@example.com 2026-04-11T16:02:00Z "Add staging credentials"
git -C "$repo" rm -q deploy/credentials
commit "Sam Example" sam@example.com 2026-04-11T16:20:00Z "Remove staging credentials"
printf 'export const client = new Api({\n  baseUrl: "https://api.example.com",\n  api_secret: "%s",\n})\n' "$(rnd 0-9BCDFGJKNRSWZbcdfgjknrswz 40)" > "$repo/src/client.js"
git -C "$repo" add -A
commit "Lee Example" lee@example.com 2026-06-23T11:45:00Z "Add API client"
printf 'SLACK_BOT_TOKEN=xoxb-%s-%s-%s\n' "$(rnd 0-9 12)" "$(rnd 0-9 12)" "$(rnd A-Za-z0-9 24)" > "$repo/config/slack.env"
git -C "$repo" add -A
commit "Dana Example" dana@example.com 2026-09-08T14:30:00Z "Add Slack alerts"
git -C "$repo" checkout -q -b feature/deploy-config
printf 'GITHUB_TOKEN=ghp_%s\nREGION=eu-north-1\n' "$(rnd A-Za-z0-9 36)" > "$repo/config/app.env"
git -C "$repo" add -A
commit "Sam Example" sam@example.com 2026-11-14T10:05:00Z "Add deploy config"
git -C "$repo" checkout -q main

# The scan exits 1 when it finds secrets, which is the point here.
scan() { (cd "$work" && "$bin" "$@" 2>&1) || test $? -eq 1; }
scan_out() { (cd "$work" && "$bin" "$@" 2>/dev/null) || test $? -eq 1; }

ex="$work/examples"
mkdir -p "$ex"
scan scan range main..feature/deploy-config --git-dir acme-payments > "$ex/range"
scan scan history --git-dir acme-payments > "$ex/history"
scan_out scan range main..feature/deploy-config --git-dir acme-payments --format markdown > "$ex/markdown"
scan_out scan range main..feature/deploy-config --git-dir acme-payments --format sarif > "$ex/sarif"
scan_out scan range main..feature/deploy-config --git-dir acme-payments --format json > "$ex/json"
scan_out scan history --git-dir acme-payments --summary > "$ex/summary"
scan_out scan history --git-dir acme-payments --format html > "$root/site/example/report.html"

# The fingerprint and the commit of the GitHub token tie the page together.
fp=$(grep -o '"fingerprint": "[0-9a-f]*"' "$ex/json" | head -1 | cut -d'"' -f4)
printf '%s' "${fp:0:12}" > "$ex/fp-short"
printf '%s' "$fp" > "$ex/fp-full"
printf '%s is now revoked' "${fp:0:12}" > "$ex/resolve"
git -C "$repo" rev-parse --short=7 feature/deploy-config | tr -d '\n' > "$ex/commit-short"

python3 - "$root/site/index.html" "$ex" <<'PY'
import html, os, re, sys
page, ex = sys.argv[1], sys.argv[2]
s = open(page, encoding="utf-8").read()
def fill(m):
    name = m.group(1)
    path = os.path.join(ex, name)
    if not os.path.exists(path):
        sys.exit(f"no example named {name}")
    text = open(path, encoding="utf-8").read().rstrip("\n")
    return f"<!-- example:{name} -->{html.escape(text, quote=False)}<!-- /example:{name} -->"
s, n = re.subn(r"<!-- example:([\w-]+) -->.*?<!-- /example:\1 -->", fill, s, flags=re.S)
open(page, "w", encoding="utf-8").write(s)
print(f"filled {n} example blocks in {page}")
PY

# Screenshots of the example report, when Chromium and ImageMagick exist:
# the full report at 1280 px, and the findings table at 420 px for phones.
browser=$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)
if [ -n "$browser" ] && command -v magick > /dev/null; then
	shoot() { # shoot <scheme> <width> <height> <url> <out.png>
		local flags=""
		[ "$1" = dark ] && flags="--force-dark-mode --blink-settings=preferredColorScheme=0"
		# shellcheck disable=SC2086
		"$browser" --headless=new --no-sandbox --disable-gpu --hide-scrollbars $flags \
			--virtual-time-budget=2000 --window-size="$2,$3" --screenshot="$5" "$4" > /dev/null 2>&1
	}
	report="file://$root/site/example/report.html"
	for scheme in light dark; do
		# A tall window, then a crop below the last content, keeps the footer whole.
		shoot "$scheme" 1280 2000 "$report" "$work/full-$scheme.png"
		h=$(magick "$work/full-$scheme.png" -fuzz 1% -format "%@" info: | sed -E 's/^[0-9]+x([0-9]+)\+[0-9]+\+([0-9]+)$/\1 \2/' | awk '{print $1 + $2 + 24}')
		magick "$work/full-$scheme.png" -crop "1280x$h+0+0" +repage -quality 88 "$root/site/assets/report-$scheme.webp"
		# At phone width, the findings table is the last panel above the
		# footer. One pixel column finds its edges: the page ground shows
		# between panels.
		shoot "$scheme" 420 2600 "$report" "$work/narrow-$scheme.png"
		box=$(magick "$work/narrow-$scheme.png" -crop 1x2600+24+0 +repage -depth 8 txt:- | python3 -c '
import re, sys
rows = [re.search(r"#([0-9A-Fa-f]{6})", l).group(1).lower() for l in sys.stdin if not l.startswith("#")]
ground = rows[2]
panel = [i for i, c in enumerate(rows) if c != ground]
# Group the rows into runs, and take the last tall run: the table.
runs, start = [], panel[0]
for a, b in zip(panel, panel[1:] + [None]):
    if b != a + 1:
        runs.append((start, a))
        start = b
tall = [r for r in runs if r[1] - r[0] > 120]
top, bottom = tall[-1]
print(top - 12, bottom - top + 24)')
		read -r top height <<< "$box"
		magick "$work/narrow-$scheme.png" -crop "420x$height+0+$top" +repage -quality 88 "$root/site/assets/report-narrow-$scheme.webp"
	done
	python3 - "$root/site" <<'PY'
import re, subprocess, sys
site = sys.argv[1]
page = site + "/index.html"
s = open(page, encoding="utf-8").read()
def size(name):
    out = subprocess.run(["magick", "identify", "-format", "%w %h", f"{site}/assets/{name}"], capture_output=True, text=True, check=True).stdout
    return out.split()
def fix(m):
    w, h = size(m.group(2))
    return re.sub(r'width="[^"]*" height="[^"]*"', f'width="{w}" height="{h}"', m.group(0))
s = re.sub(r'<(source|img) (?:srcset|src)="assets/(report-[\w-]+\.webp)"[^>]*>', fix, s)
open(page, "w", encoding="utf-8").write(s)
PY
	echo "wrote the report screenshots in site/assets"
else
	echo "no Chromium or ImageMagick: the report screenshots are not updated" >&2
fi

# A last check: the site must hold no full token.
if "$bin" scan path "$root/site" > /dev/null 2>&1; then
	echo "site/ holds no secrets"
else
	echo "site/ holds a secret-like string: check it before you commit" >&2
	exit 1
fi
