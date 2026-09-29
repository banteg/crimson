from __future__ import annotations

import math
from typing import cast

import pytest

from crimson.ui import cursor
from crimson.ui.cursor import ui_cursor_render
from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.raylib_api import rl


class _Resources:
    def texture(self, _texture_id: TextureId) -> rl.Texture:
        texture = rl.Texture()
        texture.width = 128
        texture.height = 128
        return texture


def _glow_alphas(draw_texture_pro) -> set[int]:
    # Four glow quads then the opaque arrow per render.
    return {call.args[5].a for index, call in enumerate(draw_texture_pro.call_args_list) if index % 5 != 4}


def test_cursor_pulse_is_one_global_phase_with_native_alpha(mocker) -> None:
    mocker.patch.object(cursor.rl, "begin_blend_mode")
    mocker.patch.object(cursor.rl, "end_blend_mode")
    draw = mocker.patch.object(cursor.rl, "draw_texture_pro")
    cursor._pulse.phase = 0.0
    resources = cast("RuntimeResources", _Resources())

    ui_cursor_render(resources, dt=0.5, pos=Vec2(100.0, 100.0))
    ui_cursor_render(resources, dt=0.5, pos=Vec2(100.0, 100.0))

    assert cursor._pulse.phase == pytest.approx(1.1)
    # `ui_cursor_render`: alpha = (sin(phase)^2 + 2) * 0.32, truncated to a byte.
    assert _glow_alphas(draw) == {int((math.sin(0.55) ** 2 + 2.0) * 0.32 * 255), int((math.sin(1.1) ** 2 + 2.0) * 0.32 * 255)}
