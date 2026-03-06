from __future__ import annotations

import grim.fonts.small as small_module
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_height, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl


def _font(*, width: int = 7) -> SmallFontData:
    widths = [0] * 256
    widths[ord("A")] = int(width)
    return SmallFontData(widths=widths, texture=rl.Texture())


def test_draw_small_text_uses_full_glyph_uvs_for_point_filter(mocker) -> None:
    font = _font(width=7)
    draw_texture_pro = mocker.patch.object(small_module.rl, "draw_texture_pro")

    draw_small_text(font, "A", Vec2(10.4, 20.6), rl.WHITE)

    assert draw_texture_pro.call_count == 1
    src = draw_texture_pro.call_args.args[1]
    dst = draw_texture_pro.call_args.args[2]

    assert (float(src.x), float(src.y), float(src.width), float(src.height)) == (16.0, 64.0, 7.0, 16.0)
    assert (float(dst.x), float(dst.y), float(dst.width), float(dst.height)) == (10.0, 20.0, 7.0, 16.0)


def test_small_text_metrics_are_fixed_scale() -> None:
    font = _font(width=7)
    assert measure_small_text_width(font, "A\nAA") == 14.0
    assert measure_small_text_height(font, "A\nAA") == 32.0
