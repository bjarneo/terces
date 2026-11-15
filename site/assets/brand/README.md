# terces logo

| File | Use |
|---|---|
| `terces-logo.svg` | Icon and wordmark on light grounds |
| `terces-logo-dark.svg` | Icon and wordmark on dark grounds |
| `terces-icon.svg` | Icon on light grounds |
| `terces-icon-dark.svg` | Icon on dark grounds |
| `terces-wordmark.svg` | Wordmark on light grounds |
| `terces-wordmark-dark.svg` | Wordmark on dark grounds |
| `../../favicon.svg` | Favicon. It follows the color scheme. |

The logo is "Terces Logo 1a": a dark tile with four code lines, and the wordmark in Martian Mono Medium. One code line is in the site green. The wordmark ships as outlines, so no font file loads.

| Color | Light | Dark |
|---|---|---|
| Tile | `#161513` | `#2B2A26` |
| Code lines | `#5F5C55` | `#77746C` |
| Highlighted line | `#7fb7a4` | `#7fb7a4` |
| Wordmark | `#161513` | `#F3F1EC` |

The highlighted line uses the light site green `#7fb7a4` on both tiles. The dark site green `#2f5d50` has a contrast of 2.4:1 on the tile, which is less than the gray lines.

To build the files again, run:

```bash
curl -sSfLo /tmp/MartianMono.ttf "https://github.com/google/fonts/raw/main/ofl/martianmono/MartianMono%5Bwdth,wght%5D.ttf"
uv run --no-project --with fonttools --with uharfbuzz python scripts/logo-svg.py /tmp/MartianMono.ttf /tmp/terces-logo
cp /tmp/terces-logo/terces-*.svg site/assets/brand/
cp /tmp/terces-logo/favicon.svg site/favicon.svg
```

Martian Mono is under the SIL Open Font License 1.1, copyright 2021 The Martian Mono Project Authors.
