"""Render Crimsonland main-menu buttons from Armor Piercing and the game's blank plate.

    uv run python scripts/generate_menu_buttons.py --font /path/to/ap.ttf "REPLAYS" "DAILY RUN"

Writes the clean plate, a transparent label atlas (arguments in row order),
and an RLE TGA row plus settled idle and hover PNGs for each label. Unused atlas rows are transparent.
"""

from __future__ import annotations

import argparse
import re
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

from crimson.ui.menu_layout import (
    MENU_ITEM_OFFSET_X,
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_HEIGHT,
    MENU_LABEL_OFFSET_X,
    MENU_LABEL_OFFSET_Y,
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_WIDTH,
    label_alpha,
)
from grim.assets import _select_texture_asset, load_paq_entries
from grim.jaz import decode_jaz_bytes

STOCK_ROW_WIDTH = 128
WIDE_ROW_WIDTH = 144
ROW_HEIGHT = int(MENU_LABEL_ROW_HEIGHT)
ROWS = 8
SAMPLE_WIDTH = int(MENU_LABEL_WIDTH)
FONT_SIZE = 29
SCALE = 4


def load_plate(assets: Path) -> Image.Image:
    name, data = _select_texture_asset(load_paq_entries(assets), "ui/ui_menuItem.jaz")
    if data is None:
        raise ValueError(f"Missing {name} in {assets / 'crimson.paq'}")
    if name.endswith(".jaz"):
        plate = decode_jaz_bytes(data).composite_image()
    else:
        plate = Image.open(BytesIO(data)).convert("RGBA")
    if plate.size != (512, 64):
        raise ValueError(f"Expected a 512×64 menu plate, found {plate.size}")
    return plate


def render_label(text: str, font: ImageFont.FreeTypeFont, *, row_width: int = STOCK_ROW_WIDTH) -> Image.Image:
    # The stock rows use whole-pixel advances at 29 px. Keep those positions while
    # supersampling the outlines, so the diagonals stay smooth at native size.
    if not text.strip() or not text.isprintable():
        raise ValueError("Each label must contain printable text on one line")
    missing = font.getmask("\U0010ffff")
    for char in set(text):
        glyph = font.getmask(char)
        if glyph.size == missing.size and glyph.chop_difference(missing).getbbox() is None:
            raise ValueError(f"Font has no glyph for {char!r} in {text!r}")
    hi_font = font.font_variant(size=FONT_SIZE * SCALE)
    advances = [round(font.getlength(char)) for char in text]
    if sum(advances) > row_width:
        raise ValueError(f"Label is too wide at native size: {text!r}")

    pad = 4
    mask = Image.new("L", ((row_width + pad) * SCALE, (ROW_HEIGHT + 2 * pad) * SCALE))
    draw = ImageDraw.Draw(mask)
    x = 5.25
    for char, advance in zip(text, advances, strict=True):
        draw.text((x * SCALE, (34.75 + pad) * SCALE), char, font=hi_font, fill=255, anchor="ls")
        x += advance

    # The stock atlas has a dark blue outline and a narrower blue face.
    face = mask.filter(ImageFilter.MinFilter(5))
    stroke = mask.filter(ImageFilter.MaxFilter(5))
    bounds = stroke.getbbox()
    if bounds is None:
        raise ValueError(f"Label has no visible glyphs: {text!r}")
    if bounds[2] > row_width * SCALE or bounds[1] < pad * SCALE or bounds[3] > (ROW_HEIGHT + pad) * SCALE:
        raise ValueError(f"Label overflows the row at native size: {text!r}")

    box = (0, pad * SCALE, row_width * SCALE, (ROW_HEIGHT + pad) * SCALE)
    size = (row_width, ROW_HEIGHT)
    ink = Image.new("RGBA", size, (2, 9, 12))
    outline = stroke.crop(box).resize(size, Image.Resampling.HAMMING)
    ink.putalpha(outline.point(lambda coverage: min(245, round(coverage * 245 / 224))))
    # Match the firmer edge of the stock blue face while keeping the outline's softer edge.
    blue = Image.new("RGBA", size, (26, 112, 162))
    fill = face.crop(box).resize(size, Image.Resampling.HAMMING)
    blue.putalpha(fill.point(lambda coverage: max(0, min(255, round((coverage - 82) * 255 / (199 - 82))))))
    ink.alpha_composite(blue)
    ink.paste((0, 0, 0, 0), mask=ink.getchannel("A").point(lambda opacity: 255 if opacity == 0 else 0))
    return ink


def render_button(plate: Image.Image, row: Image.Image, hover: int) -> Image.Image:
    # The settled menu draws the same tinted row twice, first source-over, then
    # additively. The panel under this entire rectangle is opaque.
    x = int(MENU_LABEL_OFFSET_X - MENU_ITEM_OFFSET_X)
    y = int(MENU_LABEL_OFFSET_Y - MENU_ITEM_OFFSET_Y)
    height = int(MENU_LABEL_HEIGHT)
    width = row.width * SAMPLE_WIDTH / STOCK_ROW_WIDTH
    # Sample the straight RGBA texture as the GPU does, at destination pixel centers.
    samples = np.asarray(row, dtype=np.float32)
    v = (np.arange(height) + 0.5) * row.height / height - 0.5
    lo = v.astype(int)
    t = (v - lo)[:, None, None]
    samples = samples[lo] * (1 - t) + samples[lo + 1] * t
    u = np.clip((np.arange(round(width)) + 0.5) * row.width / width - 0.5, 0, row.width - 1)
    lo = u.astype(int)
    t = (u - lo)[None, :, None]
    label = samples[:, lo] * (1 - t) + samples[:, np.minimum(lo + 1, row.width - 1)] * t
    a = label[:, :, 3:] * (label_alpha(hover) / 255**2)
    result = np.array(plate)
    panel = result[y : y + height, x : x + label.shape[1], :3]
    panel[:] = np.rint(np.clip(panel * (1 - a) + 2 * label[:, :, :3] * a, 0, 255))
    return Image.fromarray(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--font", required=True, type=Path, help="Path to Armor Piercing (ap.ttf)")
    parser.add_argument("--assets", type=Path, default=Path("artifacts/assets"), help="Directory with crimson.paq")
    parser.add_argument("--out", type=Path, default=Path("artifacts/menu-buttons"))
    parser.add_argument(
        "--row-width",
        type=int,
        choices=(STOCK_ROW_WIDTH, WIDE_ROW_WIDTH),
        default=STOCK_ROW_WIDTH,
        help="Texture width in pixels. Use 144 for a wider overlay at the same glyph scale.",
    )
    parser.add_argument("labels", nargs="+", help="One to eight button labels in atlas row order")
    args = parser.parse_args()
    if len(args.labels) > ROWS:
        parser.error("the native atlas holds eight labels")
    try:
        plate = load_plate(args.assets)
        font = ImageFont.truetype(args.font, FONT_SIZE, layout_engine=ImageFont.Layout.BASIC)
        rows = [render_label(label.strip(), font, row_width=args.row_width) for label in args.labels]
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    args.out.mkdir(parents=True, exist_ok=True)
    plate.save(args.out / "plate.png")
    atlas = Image.new("RGBA", (args.row_width, ROW_HEIGHT * ROWS))
    for i, (text, row) in enumerate(zip(args.labels, rows, strict=True)):
        atlas.paste(row, (0, i * ROW_HEIGHT))
        slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "label"
        row.save(args.out / f"{i:02d}-{slug}.tga", compression="tga_rle")
        for state, hover in (("idle", 0), ("hover", 1000)):
            render_button(plate, row, hover).save(args.out / f"{i:02d}-{slug}-{state}.png")
    atlas.save(args.out / "ui_itemTexts.png")
    print(f"Wrote the plate, label atlas, and {len(rows)} idle/hover pairs to {args.out}")


if __name__ == "__main__":
    main()
