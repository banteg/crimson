from __future__ import annotations

from pathlib import Path

import pytest

from crimson.screens.panels import base
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData
from grim.raylib_api import rl


@pytest.fixture
def screen_resources(tmp_path: Path) -> RuntimeResources:
    texture = rl.Texture()
    texture.width = texture.height = 32
    font = SmallFontData(widths=[8] * 256, texture=texture, cell_size=8)
    return RuntimeResources(tmp_path, {texture_id: texture for texture_id in TextureId}, font)


@pytest.fixture
def screen_io(mocker) -> None:
    for name, value in {
        "is_key_pressed": False,
        "is_key_down": False,
        "get_key_pressed": 0,
        "is_mouse_button_pressed": False,
        "is_mouse_button_down": False,
        "get_mouse_position": rl.Vector2(-1000, -1000),
        "get_mouse_wheel_move": 0.0,
        "is_gamepad_available": False,
    }.items():
        mocker.patch.object(rl, name, return_value=value)
    for name in ("draw_rectangle", "draw_rectangle_lines_ex", "draw_line", "draw_texture_pro"):
        mocker.patch.object(rl, name)
    mocker.patch.object(base, "ensure_menu_ground", return_value=None)
