from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game import loop_view as loop_module
from crimson.game.loop_view import GameLoopView
from crimson.screens import menu
from crimson.screens.actions import Route
from crimson.screens.high_scores_view import view as scores_module
from crimson.screens.panels import alien_zookeeper, base, credits, databases_base, stats
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData
from grim.raylib_api import rl


@pytest.fixture
def screen_resources(tmp_path: Path) -> RuntimeResources:
    texture = rl.Texture()
    texture.width = texture.height = 32
    font = SmallFontData(widths=[8] * 256, texture=texture, cell_size=8)
    return RuntimeResources(tmp_path, dict.fromkeys(TextureId, texture), font)


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
    for name in ("draw_rectangle", "draw_rectangle_rec", "draw_rectangle_lines_ex", "draw_line", "draw_texture_pro"):
        mocker.patch.object(rl, name)
    mocker.patch.object(base, "ensure_menu_ground", return_value=None)


@pytest.fixture
def loop(make_game_state, screen_resources, screen_io, mocker) -> GameLoopView:
    """The game loop on the main menu, with the screens' raylib input idle."""
    state = make_game_state(resources=screen_resources)
    for module in (menu, scores_module, stats, credits, alien_zookeeper, databases_base):
        mocker.patch.object(module, "ensure_menu_ground", return_value=None)
    mocker.patch.object(type(state.console), "handle_hotkey")
    mocker.patch.object(type(state.console), "update")
    mocker.patch.object(loop_module, "debug_enabled", return_value=False)
    view = GameLoopView(state)
    view.navigation.open()
    view.navigation.navigate(Route.MENU)
    return view
