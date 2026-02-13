from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.frontend.pause_menu import PAUSE_MENU_TO_MAIN_MENU_FADE_MS, PauseMenuView
from grim.config import CrimsonConfig, default_crimson_cfg_data


def _make_state() -> SimpleNamespace:
    data = default_crimson_cfg_data()
    data["screen_width"] = 640
    config = CrimsonConfig(path=Path("<memory>"), data=data)
    return SimpleNamespace(
        config=config,
        audio=None,
        pause_background=None,
        menu_sign_locked=False,
        screen_fade_alpha=0.0,
        screen_fade_ramp=False,
    )


def test_pause_menu_draw_fades_pause_background_on_main_menu_close(monkeypatch) -> None:
    captured_alpha: list[float] = []
    state = _make_state()
    state.pause_background = SimpleNamespace(
        draw_pause_background=lambda *, entity_alpha=1.0: captured_alpha.append(float(entity_alpha))
    )
    view = PauseMenuView(state)
    view._closing = True
    view._close_action = "back_to_menu"
    view._timeline_ms = PAUSE_MENU_TO_MAIN_MENU_FADE_MS // 2

    monkeypatch.setattr("crimson.frontend.pause_menu.rl.clear_background", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.frontend.pause_menu._draw_screen_fade", lambda *_args, **_kwargs: None)

    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 0.5


def test_pause_menu_draw_keeps_pause_background_alpha_for_non_menu_close(monkeypatch) -> None:
    captured_alpha: list[float] = []
    state = _make_state()
    state.pause_background = SimpleNamespace(
        draw_pause_background=lambda *, entity_alpha=1.0: captured_alpha.append(float(entity_alpha))
    )
    view = PauseMenuView(state)
    view._closing = True
    view._close_action = "back_to_previous"
    view._timeline_ms = 0

    monkeypatch.setattr("crimson.frontend.pause_menu.rl.clear_background", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.frontend.pause_menu._draw_screen_fade", lambda *_args, **_kwargs: None)

    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 1.0
