from __future__ import annotations

from pathlib import Path
import random
import time
from types import SimpleNamespace

import pyray as rl

from crimson.game import GameState, HighScoresRequest, HighScoresView
from crimson.persistence import save_status
from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import GameOverUi, PANEL_SLIDE_DURATION_MS
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def test_game_over_panel_open_plays_panel_click(monkeypatch, tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=object())
    ui.assets = object()
    ui.phase = 1
    ui._intro_ms = PANEL_SLIDE_DURATION_MS - 60.0
    ui._panel_open_sfx_played = False

    played: list[str] = []

    def _play_sfx(key: str) -> None:
        played.append(key)

    monkeypatch.setattr("crimson.ui.game_over.button_update", lambda *args, **kwargs: False)  # noqa: ARG005
    monkeypatch.setattr("crimson.ui.game_over.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.ui.game_over.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.ui.game_over.rl.get_mouse_position", lambda: SimpleNamespace(x=0.0, y=0.0))
    monkeypatch.setattr("crimson.ui.game_over.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.ui.game_over.rl.check_collision_point_rec", lambda _pos, _rect: False)
    monkeypatch.setattr("crimson.ui.game_over.rl.is_key_pressed", lambda _key: False)

    ui.update(
        0.1,
        record=HighScoreRecord.blank(),
        player_name_default="",
        play_sfx=_play_sfx,
        rand=lambda: 0,
        mouse=SimpleNamespace(x=0.0, y=0.0),
    )

    assert played == ["sfx_ui_panelclick"]


def test_high_scores_view_open_plays_panel_click_and_escape_plays_button_click(monkeypatch, tmp_path: Path) -> None:
    # Unit test: avoid depending on proprietary assets / PAQ archives.
    assets_dir = tmp_path

    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=object(),
        resource_paq=tmp_path / "crimson.paq",
        session_start=time.monotonic(),
    )
    state.pending_high_scores = HighScoresRequest(game_mode_id=1)

    played: list[str] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    monkeypatch.setattr("crimson.game.update_audio", lambda _audio, _dt: None)
    monkeypatch.setattr("crimson.game.play_sfx", _play_sfx)
    monkeypatch.setattr("crimson.game._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr(
        "crimson.game.load_menu_assets",
        lambda _state: SimpleNamespace(sign=None, item=None, panel=None, labels=None),
    )

    view = HighScoresView(state)
    view.open()

    assert played == ["sfx_ui_panelclick"]

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ESCAPE)

    # High scores view animates in; advance its timeline before pressing escape.
    monkeypatch.setattr("crimson.game.rl.is_key_pressed", lambda _key: False)
    view.update(0.1)
    view.update(0.1)
    monkeypatch.setattr("crimson.game.rl.is_key_pressed", _is_key_pressed)

    view.update(0.1)

    assert played == ["sfx_ui_panelclick", "sfx_ui_buttonclick"]
    assert view.take_action() == "back_to_previous"
