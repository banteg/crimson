from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import crimson.screens.high_scores_view.view as high_scores_view_module
import crimson.screens.results.game_over as game_over_module
from crimson.game.types import GameState, PauseBackground
from crimson.game_modes import GameMode
from crimson.persistence import save_status
from crimson.persistence.highscores import HighScoreRecord
from crimson.screens.actions import Route, ScoreQuery, ShowScores
from crimson.screens.high_scores_view import HighScoresView
from crimson.screens.panels.base import PANEL_TIMELINE_START_MS
from crimson.screens.results.game_over import PANEL_SLIDE_DURATION_MS, GameOverUi
from grim.assets import RuntimeResources
from grim.audio import AudioState
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.fonts.small import SmallFontData
from grim.music import init_music_state
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from tests.support.screens import install_background


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )


def _texture_stub() -> rl.Texture:
    return cast("rl.Texture", SimpleNamespace(width=1, height=1))


def _runtime_resources_stub(*, tex: rl.Texture | None = None) -> RuntimeResources:
    t = _texture_stub() if tex is None else tex
    small_font = cast("SmallFontData", SimpleNamespace(cell_size=8, widths=[8] * 256))
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: t,
            small_font=small_font,
        ),
    )


def test_game_over_panel_open_plays_panel_click(tmp_path: Path, mocker) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=ensure_crimson_cfg(tmp_path))
    ui.phase = 1
    ui._intro_ms = PANEL_SLIDE_DURATION_MS - 60.0
    ui._panel_open_sfx_played = False

    play_sfx = mocker.Mock()

    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_runtime_resources_stub())
    mocker.patch.object(game_over_module, "button_update", side_effect=lambda *args, **kwargs: False)
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
        rng=Crand(0),
        mouse=rl.Vector2(0.0, 0.0),
    )

    play_sfx.assert_called_once_with(SfxId.UI_PANELCLICK)


def test_high_scores_view_open_plays_panel_click_and_escape_plays_button_click(tmp_path: Path, mocker) -> None:
    # Unit test: avoid depending on proprietary assets / PAQ archives.
    assets_dir = tmp_path

    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=Crand(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        resources=None,
        audio=_audio_state_stub(),
        session_start=time.monotonic(),
    )
    state.resources = _runtime_resources_stub()

    play_sfx = mocker.Mock()

    mocker.patch.object(high_scores_view_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(high_scores_view_module, "play_sfx", side_effect=play_sfx)
    mocker.patch.object(high_scores_view_module, "ensure_menu_ground", return_value=None)

    view = HighScoresView(state, ShowScores(ScoreQuery(game_mode_id=GameMode.SURVIVAL)))
    view.open()

    assert [call.args[1] for call in play_sfx.call_args_list] == [SfxId.UI_PANELCLICK]

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ESCAPE)

    # High scores view animates in; advance its timeline before pressing escape.
    mocker.patch.object(high_scores_view_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    view.update(0.1)
    view.update(0.1)
    mocker.patch.object(high_scores_view_module.rl, "is_key_pressed", side_effect=_is_key_pressed)

    view.update(0.1)

    assert [call.args[1] for call in play_sfx.call_args_list] == [SfxId.UI_PANELCLICK, SfxId.UI_BUTTONCLICK]
    assert view.take_action() is None
    action = None
    for _ in range(30):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == Route.BACK


def test_high_scores_view_draw_fades_pause_background_during_close(tmp_path: Path, mocker) -> None:
    assets_dir = tmp_path
    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=Crand(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        resources=None,
        audio=None,
        session_start=time.monotonic(),
    )
    dummy_tex = _texture_stub()
    state.resources = _runtime_resources_stub(tex=dummy_tex)
    draw_pause_background_mock = mocker.Mock()
    install_background(
        state, cast("PauseBackground", SimpleNamespace(draw_pause_background=draw_pause_background_mock)),
    )

    mocker.patch.object(high_scores_view_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(high_scores_view_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(high_scores_view_module, "_draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(high_scores_view_module, "draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(high_scores_view_module, "draw_main_panel", side_effect=lambda *_args, **_kwargs: 0)
    mocker.patch.object(high_scores_view_module, "draw_right_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(high_scores_view_module, "_draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(HighScoresView, "_draw_sign", return_value=None)

    view = HighScoresView(state, ShowScores(ScoreQuery(game_mode_id=GameMode.SURVIVAL)))
    view.open()
    view._closing = True
    view._timeline_ms = PANEL_TIMELINE_START_MS // 2
    view.draw()

    draw_pause_background_mock.assert_called()
    assert draw_pause_background_mock.call_args.kwargs["entity_alpha"] == 0.5
