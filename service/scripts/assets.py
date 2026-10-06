"""Write the site's game art to service/public/ui/ from crimson.paq: the sign, the menu panel's frame and wires, the
quest screen's label, stage icons and checkboxes, and a terrain tile. The files are generated, not checked in;
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
        "panel.png": panel.crop(PANEL_FRAME),
        "wires.png": panel.crop(PANEL_WIRES),
        "quest.png": image("ui/ui_textQuest.tga"),
        "check-on.png": image("ui/ui_checkOn.tga"),
        "check-off.png": image("ui/ui_checkOff.tga"),
        "terrain.png": image("ter/ter_q1_base.tga").convert("RGB"),
        **{f"stage{n}.png": image(f"ui/ui_num{n}.{'jaz' if n == 5 else 'tga'}") for n in range(1, 6)},
    }
    for name, art in outputs.items():
        art.save(OUT / name, optimize=True)
    print(f"wrote {len(outputs)} images to {OUT}")


if __name__ == "__main__":
    main()
