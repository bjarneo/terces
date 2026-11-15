# terces logo

| File | Use |
|---|---|
| `terces-icon.svg` | App icon on light grounds |
| `terces-icon-dark.svg` | App icon on dark grounds |
| `terces-wordmark.svg` | Wordmark on light grounds |
| `terces-wordmark-dark.svg` | Wordmark on dark grounds |
| `../../favicon.svg` | Favicon. It uses the small-size icon and follows the color scheme. |

The logo is "Terces Logo 2b": Schibsted Grotesk ExtraBold, the top slice in ink and the bottom slice in coral, shifted to the right. The glyphs are outlines, so no font file ships.

| Color | Light | Dark |
|---|---|---|
| Ink | `#161513` | `#F3F1EC` |
| Coral | `#ed4428` | `#f84f33` |
| Icon tile | `#161513` | `#2B2A26` |

To build the files again, run:

```bash
curl -sSfLo /tmp/SchibstedGrotesk.ttf "https://github.com/google/fonts/raw/main/ofl/schibstedgrotesk/SchibstedGrotesk%5Bwght%5D.ttf"
uv run --no-project --with fonttools --with uharfbuzz python scripts/logo-svg.py /tmp/SchibstedGrotesk.ttf /tmp/terces-logo
cp /tmp/terces-logo/terces-*.svg site/assets/brand/
cp /tmp/terces-logo/favicon.svg site/favicon.svg
```

Schibsted Grotesk is under the SIL Open Font License 1.1, copyright 2023 The Schibsted-Grotesk Project Authors.
