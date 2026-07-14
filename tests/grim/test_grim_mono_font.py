from __future__ import annotations

import grim.fonts.grim_mono as mono_module
from grim.fonts.grim_mono import GrimMonoFont, draw_grim_mono_text
from grim.geom import Vec2
from grim.raylib_api import rl


def _font() -> GrimMonoFont:
    return GrimMonoFont(texture=rl.Texture())


def _rect(call, argument: int) -> tuple[float, float, float, float]:
    rect = call.args[argument]
    return float(rect.x), float(rect.y), float(rect.width), float(rect.height)


def test_draw_grim_mono_text_builds_native_composite_glyphs(mocker) -> None:
    draw_texture_pro = mocker.patch.object(mono_module.rl, "draw_texture_pro")

    draw_grim_mono_text(_font(), "äåö", Vec2(10.0, 20.0), 1.0, rl.WHITE)

    assert draw_texture_pro.call_count == 6
    calls = draw_texture_pro.call_args_list
    assert [_rect(call, 1) for call in calls] == [
        (16.0, 96.0, 16.0, 16.0),
        (32.0, 32.0, 16.0, 16.0),
        (16.0, 96.0, 16.0, 16.0),
        (224.0, 32.0, 16.0, 16.0),
        (240.0, 96.0, 16.0, 16.0),
        (32.0, 32.0, 16.0, 16.0),
    ]
    assert [_rect(call, 2) for call in calls] == [
        (26.0, 21.0, 32.0, 32.0),
        (26.0, 20.0, 32.0, 32.0),
        (42.0, 21.0, 32.0, 32.0),
        (42.0, 14.0, 32.0, 32.0),
        (58.0, 21.0, 32.0, 32.0),
        (58.0, 20.0, 32.0, 32.0),
    ]


def test_composite_glyph_does_not_consume_no_advance_marker(mocker) -> None:
    draw_texture_pro = mocker.patch.object(mono_module.rl, "draw_texture_pro")

    draw_grim_mono_text(_font(), "§äB", Vec2(10.0, 20.0), 1.0, rl.WHITE)

    assert draw_texture_pro.call_count == 3
    assert [_rect(call, 2)[0] for call in draw_texture_pro.call_args_list] == [26.0, 26.0, 26.0]
