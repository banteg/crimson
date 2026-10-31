"""Render Crimsonland main-menu buttons from Armor Piercing and the game's blank plate.

    uv run python scripts/generate_menu_buttons.py --font /path/to/ap.ttf "REPLAYS" "DAILY RUN"

Writes the clean plate, a transparent 128×256 label atlas (arguments in row order),
and a settled idle and hover PNG for each label. Unused atlas rows are transparent.
"""

from __future__ import annotations

import argparse
import math
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

ROW_SIZE = (128, int(MENU_LABEL_ROW_HEIGHT))
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


def render_label(text: str, font: ImageFont.FreeTypeFont) -> Image.Image:
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
    width = math.ceil(font.getlength(text))
    if width > 2 * (SAMPLE_WIDTH - 8):
        raise ValueError(f"Label too long to read on the plate: {text!r}")

    # Extra vertical room preserves descenders and punctuation before fitting.
    pad = 4
    mask = Image.new("L", ((width + 10) * SCALE, (ROW_SIZE[1] + 2 * pad) * SCALE))
    draw = ImageDraw.Draw(mask)
    x = 5
    for char in text:
        draw.text((x * SCALE, (34.25 + pad) * SCALE), char, font=hi_font, fill=255, anchor="ls")
        x += round(font.getlength(char))

    # The black stroke straddles the contour. Its inner half makes the lit face
    # narrower than a plain TTF render. The color is sampled from the stock atlas.
    face = mask.filter(ImageFilter.MinFilter(5))
    stroke = mask.filter(ImageFilter.MaxFilter(9))
    bounds = stroke.getbbox()
    if bounds is None:
        raise ValueError(f"Label has no visible glyphs: {text!r}")
    # Crop on the output pixel grid to keep the native letters' subpixel positions.
    left, top = bounds[0] // SCALE, bounds[1] // SCALE
    right, bottom = math.ceil(bounds[2] / SCALE), math.ceil(bounds[3] / SCALE)
    box = (left * SCALE, top * SCALE, right * SCALE, bottom * SCALE)
    # Keep the native cap height until a label would hit the edge of the sampled quad.
    width, height = right - left, bottom - top
    fit = min(1.0, (SAMPLE_WIDTH - left - 1) / width, (ROW_SIZE[1] - 2) / height)
    size = (max(1, round(width * fit)), max(1, round(height * fit)))
    ink = Image.new("RGBA", size)
    ink.putalpha(stroke.crop(box).resize(size, Image.Resampling.HAMMING))
    blue = Image.new("RGBA", size, (26, 112, 162))
    blue.putalpha(face.crop(box).resize(size, Image.Resampling.HAMMING))
    ink.alpha_composite(blue)
    y = round((top - pad - ROW_SIZE[1] / 2) * fit + ROW_SIZE[1] / 2)
    row = Image.new("RGBA", ROW_SIZE)
    row.paste(ink, (left, max(1, min(y, ROW_SIZE[1] - 1 - ink.height))))
    return row


def render_button(plate: Image.Image, row: Image.Image, hover: int) -> Image.Image:
    # The settled menu draws the same tinted row twice, first source-over, then
    # additively. The panel under this entire rectangle is opaque.
    x = int(MENU_LABEL_OFFSET_X - MENU_ITEM_OFFSET_X)
    y = int(MENU_LABEL_OFFSET_Y - MENU_ITEM_OFFSET_Y)
    height = int(MENU_LABEL_HEIGHT)
    # Sample the straight RGBA texture as the GPU does, at destination pixel centers.
    samples = np.asarray(row, dtype=np.float32)[:, :SAMPLE_WIDTH]
    v = (np.arange(height) + 0.5) * row.height / height - 0.5
    lo = v.astype(int)
    t = (v - lo)[:, None, None]
    label = samples[lo] * (1 - t) + samples[lo + 1] * t
    a = label[:, :, 3:] * (label_alpha(hover) / 255**2)
    result = np.array(plate)
    panel = result[y : y + height, x : x + SAMPLE_WIDTH, :3]
    panel[:] = np.rint(np.clip(panel * (1 - a) + 2 * label[:, :, :3] * a, 0, 255))
    return Image.fromarray(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--font", required=True, type=Path, help="Path to Armor Piercing (ap.ttf)")
    parser.add_argument("--assets", type=Path, default=Path("artifacts/assets"), help="Directory with crimson.paq")
    parser.add_argument("--out", type=Path, default=Path("artifacts/menu-buttons"))
    parser.add_argument("labels", nargs="+", help="One to eight button labels in atlas row order")
    args = parser.parse_args()
    if len(args.labels) > ROWS:
        parser.error("the native atlas holds eight labels")
    try:
        plate = load_plate(args.assets)
        font = ImageFont.truetype(args.font, FONT_SIZE, layout_engine=ImageFont.Layout.BASIC)
        rows = [render_label(label.strip(), font) for label in args.labels]
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    args.out.mkdir(parents=True, exist_ok=True)
    plate.save(args.out / "plate.png")
    atlas = Image.new("RGBA", (ROW_SIZE[0], ROW_SIZE[1] * ROWS))
    for i, (text, row) in enumerate(zip(args.labels, rows, strict=True)):
        atlas.paste(row, (0, i * ROW_SIZE[1]))
        slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "label"
        for state, hover in (("idle", 0), ("hover", 1000)):
            render_button(plate, row, hover).save(args.out / f"{i:02d}-{slug}-{state}.png")
    atlas.save(args.out / "ui_itemTexts.png")
    print(f"Wrote the plate, label atlas, and {len(rows)} idle/hover pairs to {args.out}")


if __name__ == "__main__":
    main()
