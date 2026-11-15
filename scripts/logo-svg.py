#!/usr/bin/env python3
# logo-svg.py builds the terces logo SVGs. See site/assets/brand/README.md.
# Builds the terces logo SVGs from the design "Terces Logo 2b":
# Schibsted Grotesk ExtraBold, the top slice in ink, the bottom slice in
# coral, shifted to the right.
import math, sys, os
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

font_path, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
WGHT = 800
tt = TTFont(font_path)
upm = tt["head"].unitsPerEm
gs = tt.getGlyphSet(location={"wght": WGHT})
os2, hhea = tt["OS/2"], tt["hhea"]
if os2.fsSelection & (1 << 7):
    asc, desc = os2.sTypoAscender, -os2.sTypoDescender
else:
    asc, desc = hhea.ascent, -hhea.descent

blob = hb.Blob.from_file_path(font_path)
hbfont = hb.Font(hb.Face(blob))
hbfont.set_variations({"wght": WGHT})

def oklch_hex(L, C, h):
    a, b = C * math.cos(math.radians(h)), C * math.sin(math.radians(h))
    l_ = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3
    r = 4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_
    g = -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_
    bb = -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_
    def enc(x):
        x = min(1, max(0, x))
        return 12.92 * x if x <= 0.0031308 else 1.055 * x ** (1 / 2.4) - 0.055
    return "#" + "".join(f"{round(enc(v) * 255):02x}" for v in (r, g, bb))

CORAL, CORAL_DARK = oklch_hex(0.63, 0.21, 32), oklch_hex(0.66, 0.21, 32)
INK, PAPER, PAPER_DARK, TILE_DARK = "#161513", "#FAF9F6", "#F3F1EC", "#2B2A26"
print("coral", CORAL, "coral dark", CORAL_DARK)

def shape(text, size, letter_spacing=0.0):
    """Returns one SVG path for text at size, the advance width and the baseline for line-height 1."""
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(hbfont, buf, {"kern": True, "liga": True})
    scale = size / upm
    baseline = (size - (asc + desc) * scale) / 2 + asc * scale
    x = 0.0
    pen = SVGPathPen(gs, ntos=lambda v: ("%.1f" % v).rstrip("0").rstrip("."))
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        name = tt.getGlyphName(info.codepoint)
        tp = TransformPen(pen, (scale, 0, 0, -scale, x + pos.x_offset * scale, baseline - pos.y_offset * scale))
        gs[name].draw(tp)
        x += pos.x_advance * scale + letter_spacing * size
    return pen.getCommands(), x, baseline

def r(v):
    return f"{v:.2f}".rstrip("0").rstrip(".")

def wordmark(ink, coral, title=True):
    size, ls = 100.0, -0.045
    d, width, _ = shape("terces", size, ls)
    shift = 0.06 * size
    W, H = width + shift, size
    t = '<title>terces</title>' if title else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {r(W)} {r(H)}" role="img" aria-label="terces">{t}'
            f'<defs><clipPath id="wt"><rect width="{r(width)}" height="55"/></clipPath>'
            f'<clipPath id="wb"><rect y="56" width="{r(width)}" height="44"/></clipPath></defs>'
            f'<path clip-path="url(#wt)" fill="{ink}" d="{d}"/>'
            f'<g transform="translate({r(shift)} 0)"><path clip-path="url(#wb)" fill="{coral}" d="{d}"/></g></svg>')

def icon_parts(small=False):
    size = 100.0
    gsize = (0.9 if small else 0.86) * size
    shift = (0.1 if small else 0.07) * gsize
    d, adv, _ = shape("t", gsize)
    top = (size - gsize) / 2
    x0 = (size - adv) / 2
    return d, x0, top, shift

def icon(tile, ink, coral, small=False, style=None):
    d, x0, top, shift = icon_parts(small)
    g = f'transform="translate({r(x0)} {r(top)})"'
    st = f"<style>{style}</style>" if style else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" role="img" aria-label="terces">{st}'
            f'<defs><clipPath id="sq"><rect width="100" height="100" rx="20"/></clipPath>'
            f'<clipPath id="it"><rect width="100" height="55"/></clipPath>'
            f'<clipPath id="ib"><rect y="57" width="100" height="43"/></clipPath></defs>'
            f'<g clip-path="url(#sq)"><rect class="tile" width="100" height="100" fill="{tile}"/>'
            f'<g clip-path="url(#it)"><path class="ink" fill="{ink}" {g} d="{d}"/></g>'
            f'<g clip-path="url(#ib)"><g transform="translate({r(shift)} 0)"><path class="coral" fill="{coral}" {g} d="{d}"/></g></g></g></svg>')

files = {
    "terces-wordmark.svg": wordmark(INK, CORAL),
    "terces-wordmark-dark.svg": wordmark(PAPER_DARK, CORAL_DARK),
    "terces-icon.svg": icon(INK, PAPER, CORAL),
    "terces-icon-dark.svg": icon(TILE_DARK, PAPER_DARK, CORAL_DARK),
    "favicon.svg": icon(INK, PAPER, CORAL, small=True,
        style=f"@media (prefers-color-scheme:dark){{.tile{{fill:{TILE_DARK}}}.ink{{fill:{PAPER_DARK}}}.coral{{fill:{CORAL_DARK}}}}}"),
}
for name, svg in files.items():
    open(os.path.join(out_dir, name), "w").write(svg + "\n")
    print(name, len(svg), "bytes")
