from __future__ import annotations

from pathlib import Path
import random

import pyray as rl

from crimson.modes.survival_mode import SurvivalMode
from grim.view import ViewContext


def _make_survival_mode() -> SurvivalMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    mode = SurvivalMode(ctx)
    mode._world.audio_router.audio = object()
    mode._world.audio_router.audio_rng = random.Random(0)
    return mode


def test_open_perk_menu_plays_panel_click(monkeypatch) -> None:
    mode = _make_survival_mode()
    mode._state.perk_selection.pending_count = 1

    played: list[str | None] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.audio_router.play_sfx", _play_sfx)

    mode._open_perk_menu()

    assert played == ["sfx_ui_panelclick"]


def test_perk_menu_pick_plays_button_click(monkeypatch) -> None:
    mode = _make_survival_mode()
    mode._perk_menu_assets = object()
    mode._perk_menu_open = True
    mode._state.perk_selection.pending_count = 1

    played: list[str | None] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.audio_router.play_sfx", _play_sfx)

    monkeypatch.setattr("crimson.modes.survival_mode.button_update", lambda *args, **kwargs: False)  # noqa: ARG005
    monkeypatch.setattr("crimson.modes.survival_mode.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.check_collision_point_rec", lambda _pos, _rect: False)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.measure_text", lambda _text, _size: 10)

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ENTER)

    monkeypatch.setattr("crimson.modes.survival_mode.rl.is_key_pressed", _is_key_pressed)

    mode._perk_menu_handle_input(0.0)

    assert played == ["sfx_ui_buttonclick"]
    assert mode._perk_menu_open is False


def test_perk_menu_cancel_plays_button_click(monkeypatch) -> None:
    mode = _make_survival_mode()
    mode._perk_menu_assets = object()
    mode._perk_menu_open = True

    played: list[str | None] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.audio_router.play_sfx", _play_sfx)

    monkeypatch.setattr("crimson.modes.survival_mode.button_update", lambda *args, **kwargs: True)  # noqa: ARG005
    monkeypatch.setattr("crimson.modes.survival_mode.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.check_collision_point_rec", lambda _pos, _rect: False)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.measure_text", lambda _text, _size: 10)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.is_key_pressed", lambda _key: False)

    mode._perk_menu_handle_input(0.0)

    assert played == ["sfx_ui_buttonclick"]
    assert mode._perk_menu_open is False
