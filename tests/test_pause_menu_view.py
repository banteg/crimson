from __future__ import annotations

from typing import cast

import pyray as rl

from crimson.frontend.assets import MenuAssets
from crimson.frontend.pause_menu import PAUSE_MENU_TO_MAIN_MENU_FADE_MS, PauseMenuView


def _texture_stub() -> rl.Texture:
    return cast("rl.Texture", type("_TextureStub", (), {"width": 1, "height": 1})())


class _PauseBackgroundStub:
    def __init__(self, sink: list[float]) -> None:
        self._sink = sink

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        self._sink.append(float(entity_alpha))


def test_pause_menu_draw_fades_pause_background_on_main_menu_close(monkeypatch, make_game_state) -> None:
    captured_alpha: list[float] = []
    state = make_game_state(
        config_updates={"screen_width": 640},
        menu_sign_locked=False,
        screen_fade_alpha=0.0,
        screen_fade_ramp=False,
    )
    state.pause_background = _PauseBackgroundStub(captured_alpha)
    view = PauseMenuView(state)
    view._is_open = True
    dummy_tex = _texture_stub()
    view._assets = MenuAssets(sign=dummy_tex, item=dummy_tex, panel=dummy_tex, labels=dummy_tex)
    view._closing = True
    view._close_action = "back_to_menu"
    view._timeline_ms = PAUSE_MENU_TO_MAIN_MENU_FADE_MS // 2

    monkeypatch.setattr("crimson.frontend.pause_menu.rl.clear_background", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.frontend.pause_menu._draw_screen_fade", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(PauseMenuView, "_draw_menu_items", lambda _self: None)
    monkeypatch.setattr(PauseMenuView, "_draw_menu_sign", lambda _self: None)
    monkeypatch.setattr("crimson.frontend.pause_menu._draw_menu_cursor", lambda *_args, **_kwargs: None)

    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 0.5


def test_pause_menu_draw_keeps_pause_background_alpha_for_non_menu_close(monkeypatch, make_game_state) -> None:
    captured_alpha: list[float] = []
    state = make_game_state(
        config_updates={"screen_width": 640},
        menu_sign_locked=False,
        screen_fade_alpha=0.0,
        screen_fade_ramp=False,
    )
    state.pause_background = _PauseBackgroundStub(captured_alpha)
    view = PauseMenuView(state)
    view._is_open = True
    dummy_tex = _texture_stub()
    view._assets = MenuAssets(sign=dummy_tex, item=dummy_tex, panel=dummy_tex, labels=dummy_tex)
    view._closing = True
    view._close_action = "back_to_previous"
    view._timeline_ms = 0

    monkeypatch.setattr("crimson.frontend.pause_menu.rl.clear_background", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.frontend.pause_menu._draw_screen_fade", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(PauseMenuView, "_draw_menu_items", lambda _self: None)
    monkeypatch.setattr(PauseMenuView, "_draw_menu_sign", lambda _self: None)
    monkeypatch.setattr("crimson.frontend.pause_menu._draw_menu_cursor", lambda *_args, **_kwargs: None)

    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 1.0
