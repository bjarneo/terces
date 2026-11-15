#!/usr/bin/env python3
# logo-svg.py builds the terces logo SVGs. See site/assets/brand/README.md.
#
# The logo is "Terces Logo 1a": a dark tile with four code lines, one of
# them in the site green, and the wordmark in Martian Mono Medium. The
# wordmark ships as outlines, so no font file loads.
#
# Usage: logo-svg.py <MartianMono.ttf> <output directory>
import os
import sys

import uharfbuzz as hb
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

font_path, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
AXES = {"wght": 500, "wdth": 100}

LIGHT = {"tile": "#161513", "bar": "#5F5C55", "accent": "#7fb7a4", "ink": "#161513"}
DARK = {"tile": "#2B2A26", "bar": "#77746C", "accent": "#7fb7a4", "ink": "#F3F1EC"}

tt = TTFont(font_path)
upm = tt["head"].unitsPerEm
gs = tt.getGlyphSet(location=AXES)
os2, hhea = tt["OS/2"], tt["hhea"]
if os2.fsSelection & (1 << 7):
    asc, desc = os2.sTypoAscender, -os2.sTypoDescender
else:
    asc, desc = hhea.ascent, -hhea.descent
hbfont = hb.Font(hb.Face(hb.Blob.from_file_path(font_path)))
hbfont.set_variations(AXES)


def num(v):
    return ("%.1f" % v).rstrip("0").rstrip(".")


def wordmark_path(size, letter_spacing):
    """Returns the path of "terces", its advance width and its ink bounds,
    with the line box of line-height 1 from y=0 to y=size."""
    buf = hb.Buffer()
    buf.add_str("terces")
    buf.guess_segment_properties()
    hb.shape(hbfont, buf, {"kern": True})
    scale = size / upm
    baseline = (size - (asc + desc) * scale) / 2 + asc * scale
    pen, bounds = SVGPathPen(gs, ntos=num), BoundsPen(gs)
    x = 0.0
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        t = (scale, 0, 0, -scale, x + pos.x_offset * scale, baseline - pos.y_offset * scale)
        glyph = gs[tt.getGlyphName(info.codepoint)]
        glyph.draw(TransformPen(pen, t))
        glyph.draw(TransformPen(bounds, t))
        x += pos.x_advance * scale + letter_spacing * size
    return pen.getCommands(), x, bounds.bounds


def icon_body(c, size=100.0, x0=0.0, y0=0.0):
    """The tile and its four bars, from the design: padding 0.2em, bar
    height 0.08em, gap 0.075em, the group centered on the tile."""
    u = size / 100
    bars = [(20, 34, "bar"), (30, 40, "bar"), (30, 50, "accent"), (20, 22, "bar")]
    top = (100 - (4 * 8 + 3 * 7.5)) / 2
    out = [f'<rect x="{num(x0)}" y="{num(y0)}" width="{num(size)}" height="{num(size)}" rx="{num(22 * u)}" fill="{c["tile"]}"/>']
    for i, (x, w, role) in enumerate(bars):
        y = top + i * (8 + 7.5)
        out.append(f'<rect x="{num(x0 + x * u)}" y="{num(y0 + y * u)}" width="{num(w * u)}" height="{num(8 * u)}" rx="{num(2 * u)}" fill="{c[role]}"/>')
    return "".join(out)


def svg(view_w, view_h, body, label="terces"):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {num(view_w)} {num(view_h)}" '
            f'role="img" aria-label="{label}"><title>{label}</title>{body}</svg>\n')


files = {}
for suffix, c in (("", LIGHT), ("-dark", DARK)):
    files[f"terces-icon{suffix}.svg"] = svg(100, 100, icon_body(c))
    # The wordmark alone, cropped to its ink with a small margin.
    d, adv, (x1, y1, x2, y2) = wordmark_path(100.0, -0.04)
    pad = 2
    files[f"terces-wordmark{suffix}.svg"] = svg(
        x2 - x1 + 2 * pad, y2 - y1 + 2 * pad,
        f'<path transform="translate({num(pad - x1)} {num(pad - y1)})" fill="{c["ink"]}" d="{d}"/>')
    # The lockup from the design: a 120 icon, a 36 gap and a 92 wordmark,
    # centered on one line.
    d, adv, _ = wordmark_path(92.0, -0.04)
    body = icon_body(c, 120) + f'<path transform="translate(156 14)" fill="{c["ink"]}" d="{d}"/>'
    files[f"terces-logo{suffix}.svg"] = svg(156 + adv, 120, body)

style = ("<style>@media (prefers-color-scheme:dark){" +
         f'.t{{fill:{DARK["tile"]}}}.b{{fill:{DARK["bar"]}}}' + "}</style>")
fav = icon_body(LIGHT).replace(f'fill="{LIGHT["tile"]}"', f'class="t" fill="{LIGHT["tile"]}"', 1)
fav = fav.replace(f'fill="{LIGHT["bar"]}"', f'class="b" fill="{LIGHT["bar"]}"')
files["favicon.svg"] = svg(100, 100, style + fav)

for name, content in files.items():
    with open(os.path.join(out_dir, name), "w") as f:
        f.write(content)
    print(name, len(content), "bytes")
