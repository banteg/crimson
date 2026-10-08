"""Write the site's game art to service/public/ui/ from crimson.paq: the sign, the menu panel's frame and wires, the
button plates, the main menu's Play Game item, the quest screen's label, stage icons and checkboxes, and the terrain textures the browser stamps the ground with. The files are generated, not checked in;
`npm run deploy` writes them first.

Run from the repository root: uv run python service/scripts/assets.py [--assets artifacts/assets]
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

from PIL import Image

from grim.assets import load_paq_entries
from grim.jaz import decode_jaz_bytes

OUT = Path(__file__).resolve().parents[1] / "public" / "ui"
# ui_menuPanel.tga: the frame and its black screen, right of the wire connector, and the connector itself.
PANEL_FRAME = (178, 14, 500, 248)
PANEL_WIRES = (0, 30, 192, 80)
# ui_menuItem.tga: the plate and its cable, without the rod that runs off the screen's left edge; ui_itemTexts.tga's
# Play Game row, as wide as ui_element_render samples it.
MENU_ITEM = (256, 8, 512, 64)
PLAY_GAME_LABEL = (0, 32, 122, 64)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=Path, default=Path("artifacts/assets"))
    entries = load_paq_entries(parser.parse_args().assets)

    def image(name: str) -> Image.Image:
        data = entries[name]
        return decode_jaz_bytes(data).composite_image() if name.endswith(".jaz") else Image.open(io.BytesIO(data)).convert("RGBA")

    OUT.mkdir(parents=True, exist_ok=True)
    panel = image("ui/ui_menuPanel.tga")
    outputs = {
        "sign.png": image("ui/ui_signCrimson.tga"),
        "weapons.png": image("ui/ui_wicons.tga" if "ui/ui_wicons.tga" in entries else "ui/ui_wicons.jaz"),
        "panel.png": panel.crop(PANEL_FRAME),
        "wires.png": panel.crop(PANEL_WIRES),
        "check-on.png": image("ui/ui_checkOn.tga"),
        "button-sm.png": image("ui/ui_button_64x32.jaz"),
        "button-md.png": image("ui/ui_button_128x32.jaz"),
        "check-off.png": image("ui/ui_checkOff.tga"),
        "menu-item.png": image("ui/ui_menuItem.tga").crop(MENU_ITEM),
        "play-game.png": image("ui/ui_itemTexts.tga").crop(PLAY_GAME_LABEL),
        # Terrain textures by the game's slot number (src/crimson/terrain_slots.py): base, then overlay, per quest stage.
        **{f"ter{2 * q + layer}.png": image(f"ter/ter_q{q + 1}_{'base' if layer == 0 else 'tex1'}.tga") for q in range(4) for layer in (0, 1)},
        **{f"stage{n}.png": image(f"ui/ui_num{n}.{'jaz' if n == 5 else 'tga'}") for n in range(1, 6)},
    }
    for name, art in outputs.items():
        art.save(OUT / name, optimize=True)
    # The site's pages read the WOFF2; the Worker's preview cards (src/card.ts) render with the TrueType.
    font = small_font(image("load/smallWhite.tga"), entries["load/smallFnt.dat"])
    font.save(OUT / "small.ttf")
    font.flavor = "woff2"
    font.save(OUT / "small.woff2")
    print(f"wrote {len(outputs)} images and the small font to {OUT}")


# The game's small font (grim's "pixel Arial"): 16x16 cells of one-bit glyphs, their advances in smallFnt.dat,
# capitals on rows 4..11 above a baseline at row 12. Each lit pixel becomes a square 100 units wide in a
# 1600-unit em, so at 16 CSS pixels a font pixel covers a screen pixel.
PIXEL = 100
CELL = 16
BASELINE_ROW = 12


def small_font(sheet: Image.Image, widths: bytes):
    from fontTools.fontBuilder import FontBuilder
    from fontTools.pens.ttGlyphPen import TTGlyphPen

    alpha = sheet.getchannel("A")
    glyphs, advances, cmap = {".notdef": TTGlyphPen(None).glyph()}, {".notdef": (8 * PIXEL, 0)}, {}
    for code in range(32, 256):
        if not widths[code]:
            continue
        pen = TTGlyphPen(None)
        col, row = code % CELL, code // CELL
        for y in range(CELL):
            x = 0
            while x < widths[code]:
                if alpha.getpixel((col * CELL + x, row * CELL + y)) < 128:
                    x += 1
                    continue
                start = x
                while x < widths[code] and alpha.getpixel((col * CELL + x, row * CELL + y)) >= 128:
                    x += 1
                top, bottom = (BASELINE_ROW - y) * PIXEL, (BASELINE_ROW - y - 1) * PIXEL
                pen.moveTo((start * PIXEL, bottom))
                pen.lineTo((start * PIXEL, top))
                pen.lineTo((x * PIXEL, top))
                pen.lineTo((x * PIXEL, bottom))
                pen.closePath()
        name = f"uni{code:04X}"
        glyphs[name] = pen.glyph()
        advances[name] = (widths[code] * PIXEL, 0)
        cmap[code] = name
    builder = FontBuilder(CELL * PIXEL, isTTF=True)
    builder.setupGlyphOrder(list(glyphs))
    builder.setupCharacterMap(cmap)
    builder.setupGlyf(glyphs)
    builder.setupHorizontalMetrics(advances)
    builder.setupHorizontalHeader(ascent=BASELINE_ROW * PIXEL, descent=-(CELL - BASELINE_ROW) * PIXEL)
    builder.setupNameTable({"familyName": "Crimson Small", "styleName": "Regular", "fullName": "Crimson Small", "psName": "CrimsonSmall-Regular"})
    builder.setupOS2(sTypoAscender=BASELINE_ROW * PIXEL, sTypoDescender=-(CELL - BASELINE_ROW) * PIXEL, sTypoLineGap=0,
                     usWinAscent=BASELINE_ROW * PIXEL, usWinDescent=(CELL - BASELINE_ROW) * PIXEL)
    builder.setupPost()
    return builder.font


if __name__ == "__main__":
    main()
