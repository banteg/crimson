from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import crimson.screens.pause_menu as pause_menu_module
from crimson.screens.actions import Route
from crimson.screens.pause_menu import PAUSE_MENU_TO_MAIN_MENU_FADE_MS, PauseMenuView
from grim.assets import RuntimeResources
from grim.raylib_api import rl
from tests.support.screens import install_background


def _texture_stub() -> rl.Texture:
    return cast("rl.Texture", type("_TextureStub", (), {"width": 1, "height": 1})())


def _resources_stub() -> RuntimeResources:
    tex = _texture_stub()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: tex,
            small_font=SimpleNamespace(cell_size=8, widths=[8] * 256),
        ),
    )


def test_pause_menu_draw_fades_pause_background_on_main_menu_close(make_game_state, mocker) -> None:
    state = make_game_state(
        config_updates={"screen_width": 640},
        menu_sign_locked=False,
        screen_fade_alpha=0.0,
        screen_fade_ramp=False,
    )
    pause_background = mocker.Mock()
    install_background(state, pause_background)
    state.resources = _resources_stub()
    view = PauseMenuView(state)
    view._is_open = True
    view._closing = True
    view._close_action = Route.MENU
    view._timeline_ms = PAUSE_MENU_TO_MAIN_MENU_FADE_MS // 2

    mocker.patch.object(pause_menu_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(pause_menu_module, "_draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(PauseMenuView, "_draw_menu_items", side_effect=lambda: None)
    mocker.patch.object(PauseMenuView, "_draw_menu_sign", side_effect=lambda: None)
    mocker.patch.object(pause_menu_module, "_draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)

    view.draw()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=0.5)


def test_pause_menu_draw_keeps_pause_background_alpha_for_non_menu_close(make_game_state, mocker) -> None:
    state = make_game_state(
        config_updates={"screen_width": 640},
        menu_sign_locked=False,
        screen_fade_alpha=0.0,
        screen_fade_ramp=False,
    )
    pause_background = mocker.Mock()
    install_background(state, pause_background)
    state.resources = _resources_stub()
    view = PauseMenuView(state)
    view._is_open = True
    view._closing = True
    view._close_action = Route.BACK
    view._timeline_ms = 0

    mocker.patch.object(pause_menu_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(pause_menu_module, "_draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(PauseMenuView, "_draw_menu_items", side_effect=lambda: None)
    mocker.patch.object(PauseMenuView, "_draw_menu_sign", side_effect=lambda: None)
    mocker.patch.object(pause_menu_module, "_draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)

    view.draw()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=1.0)
