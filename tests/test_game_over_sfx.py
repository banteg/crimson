from __future__ import annotations

import random
import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import crimson.game.high_scores_view.view as high_scores_view_module
import crimson.ui.game_over as game_over_module
from crimson.frontend.assets import MenuAssets
from crimson.frontend.panels.base import PANEL_TIMELINE_START_MS
from crimson.game.high_scores_view import HighScoresView
from crimson.game.types import GameState, HighScoresRequest
from crimson.persistence import save_status
from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import PANEL_SLIDE_DURATION_MS, GameOverAssets, GameOverUi
from crimson.ui.perk_menu import PerkMenuAssets
from grim.audio import AudioState
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.music import init_music_state
from grim.raylib_api import rl
from grim.sfx import init_sfx_state


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )


def _texture_stub() -> rl.Texture:
    return cast("rl.Texture", SimpleNamespace(width=1, height=1))


def _menu_assets_stub(*, tex: rl.Texture | None = None) -> MenuAssets:
    t = _texture_stub() if tex is None else tex
    return MenuAssets(sign=t, item=t, panel=t, labels=t)


def _game_over_assets_stub() -> GameOverAssets:
    return GameOverAssets(
        menu_panel=None,
        text_reaper=None,
        text_well_done=None,
        particles=None,
        perk_menu_assets=PerkMenuAssets(
            menu_panel=None,
            title_pick_perk=None,
            title_level_up=None,
            menu_item=None,
            button_sm=None,
            button_md=None,
            cursor=None,
            aim=None,
        ),
    )


class _PauseBackgroundStub:
    def __init__(self, sink: list[float]) -> None:
        self._sink = sink

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        self._sink.append(float(entity_alpha))


def test_game_over_panel_open_plays_panel_click(monkeypatch, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=ensure_crimson_cfg(tmp_path))
    ui.assets = _game_over_assets_stub()
    ui.phase = 1
    ui._intro_ms = PANEL_SLIDE_DURATION_MS - 60.0
    ui._panel_open_sfx_played = False

    play_sfx = mocker.Mock()

    mocker.patch("crimson.ui.game_over.button_update", side_effect=lambda *args, **kwargs: False)
    mocker.patch.object(game_over_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(game_over_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(game_over_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(game_over_module.rl, "is_mouse_button_pressed", side_effect=lambda _button: False)
    mocker.patch.object(game_over_module.rl, "check_collision_point_rec", side_effect=lambda _pos, _rect: False)
    mocker.patch.object(game_over_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    ui.update(
        0.1,
        record=HighScoreRecord.blank(),
        player_name_default="",
        play_sfx=play_sfx,
        rand=lambda: 0,
        mouse=rl.Vector2(0.0, 0.0),
    )

    play_sfx.assert_called_once_with("sfx_ui_panelclick")


def test_high_scores_view_open_plays_panel_click_and_escape_plays_button_click(monkeypatch, tmp_path: Path, mocker) -> None:
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
        audio=_audio_state_stub(),
        resource_paq=tmp_path / "crimson.paq",
        session_start=time.monotonic(),
    )
    state.pending_high_scores = HighScoresRequest(game_mode_id=1)

    play_sfx = mocker.Mock()

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):
            return SimpleNamespace(texture=None)

    mocker.patch("crimson.game.high_scores_view.view.update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch("crimson.game.high_scores_view.view.play_sfx", side_effect=play_sfx)
    mocker.patch("crimson.game.high_scores_view.view._ensure_texture_cache", side_effect=lambda _state: _DummyCache())
    mocker.patch.object(high_scores_view_module, "load_menu_assets", side_effect=lambda _state: _menu_assets_stub())

    view = HighScoresView(state)
    view.open()

    assert [call.args[1] for call in play_sfx.call_args_list] == ["sfx_ui_panelclick"]

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ESCAPE)

    # High scores view animates in; advance its timeline before pressing escape.
    mocker.patch.object(high_scores_view_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    view.update(0.1)
    view.update(0.1)
    mocker.patch.object(high_scores_view_module.rl, "is_key_pressed", side_effect=_is_key_pressed)

    view.update(0.1)

    assert [call.args[1] for call in play_sfx.call_args_list] == ["sfx_ui_panelclick", "sfx_ui_buttonclick"]
    assert view.take_action() is None
    action = None
    for _ in range(30):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "back_to_previous"


def test_high_scores_view_draw_fades_pause_background_during_close(monkeypatch, tmp_path: Path, mocker) -> None:
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
        audio=None,
        resource_paq=tmp_path / "crimson.paq",
        session_start=time.monotonic(),
    )
    state.pending_high_scores = HighScoresRequest(game_mode_id=1)
    captured_alpha: list[float] = []
    state.pause_background = _PauseBackgroundStub(captured_alpha)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):
            return SimpleNamespace(texture=None)

    dummy_tex = _texture_stub()
    mocker.patch("crimson.game.high_scores_view.view.update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch("crimson.game.high_scores_view.view._ensure_texture_cache", side_effect=lambda _state: _DummyCache())
    mocker.patch.object(high_scores_view_module, "load_menu_assets", side_effect=lambda _state: _menu_assets_stub(tex=dummy_tex))
    mocker.patch.object(high_scores_view_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.game.high_scores_view.view._draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.game.high_scores_view.view.draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.game.high_scores_view.view.draw_main_panel", side_effect=lambda *_args, **_kwargs: 0)
    mocker.patch("crimson.game.high_scores_view.view.draw_right_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.game.high_scores_view.view._draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    monkeypatch.setattr(HighScoresView, "_ensure_small_font", lambda _self: SimpleNamespace(texture=dummy_tex))
    monkeypatch.setattr(HighScoresView, "_draw_sign", lambda _self, _assets: None)

    view = HighScoresView(state)
    view.open()
    view._closing = True
    view._timeline_ms = PANEL_TIMELINE_START_MS // 2
    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 0.5
