from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.rush_mode import RushMode
from crimson.persistence.highscores import HighScoreRecord
from crimson.screens.results.game_over import PANEL_SLIDE_DURATION_MS, GameOverUi
from crimson.sim.sessions import DeterministicSession
from grim.audio import AudioState
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from grim.view import ViewContext


def _make_mode(*, config) -> RushMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    mode = RushMode(ctx, config=config, audio_rng=Crand(0xBEEF))
    mode._game_over_active = True
    mode._game_over_record = HighScoreRecord.blank()
    return mode


def test_update_game_over_ui_routes_high_scores(mocker, make_mode_config) -> None:
    mode = _make_mode(config=make_mode_config(game_mode=GameMode.RUSH))

    def _update(*_args, **_kwargs):
        return "high_scores"

    mocker.patch.object(GameOverUi, "update", side_effect=_update)

    mode._update_game_over_ui(0.1)

    assert mode.take_action() == "open_high_scores"
    assert mode.close_requested is False


def test_update_game_over_ui_routes_main_menu(mocker, make_mode_config) -> None:
    mode = _make_mode(config=make_mode_config(game_mode=GameMode.RUSH))

    def _update(*_args, **_kwargs):
        return "main_menu"

    mocker.patch.object(GameOverUi, "update", side_effect=_update)

    mode._update_game_over_ui(0.1)

    assert mode.take_action() == "back_to_menu"
    assert mode.close_requested is True


def test_update_game_over_ui_calls_open_on_play_again(mocker, make_mode_config) -> None:
    mode = _make_mode(config=make_mode_config(game_mode=GameMode.RUSH))
    open_mode = mocker.patch.object(mode, "open")

    def _update(*_args, **_kwargs):
        return "play_again"

    mocker.patch.object(GameOverUi, "update", side_effect=_update)

    mode._update_game_over_ui(0.1)

    open_mode.assert_called_once_with()
    assert mode.take_action() is None


def test_open_stops_music_before_run_restart(mocker, make_mode_config) -> None:
    mode = _make_mode(config=make_mode_config(game_mode=GameMode.RUSH))
    mode.audio = AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )
    stop_music = mocker.patch.object(base_gameplay_mode, "stop_music")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=SimpleNamespace(texture=None))
    mocker.patch.object(base_gameplay_mode.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(base_gameplay_mode.rl, "get_screen_height", return_value=768)
    mocker.patch.object(base_gameplay_mode.rl, "get_render_width", return_value=1024)
    mocker.patch.object(base_gameplay_mode.rl, "get_render_height", return_value=768)
    mocker.patch.object(mode.world_runtime, "reset", side_effect=lambda **_kwargs: None)
    mocker.patch.object(mode.world_runtime, "open_runtime", side_effect=lambda: None)
    mocker.patch.object(mode._local_input, "reset", side_effect=lambda **_kwargs: None)

    base_gameplay_mode.BaseGameplayMode.open(mode)

    stop_music.assert_called_once_with(mode.audio)


def test_draw_pause_background_fades_entities_during_game_over_close(mocker, make_mode_config) -> None:
    mode = _make_mode(config=make_mode_config(game_mode=GameMode.RUSH))
    mode._game_over_ui._closing = True
    mode._game_over_ui._intro_ms = PANEL_SLIDE_DURATION_MS * 0.5

    world_draw = mocker.patch.object(mode, "_draw_world")

    mode.draw_pause_background()

    world_draw.assert_called_once()
    assert world_draw.call_args.kwargs["draw_aim_indicators"] is False
    assert world_draw.call_args.kwargs["entity_alpha"] == 0.5


def test_rush_elapsed_helpers_use_authoritative_session_timer(mocker, make_mode_config) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    config = make_mode_config(game_mode=GameMode.RUSH)
    mode = RushMode(ctx, config=config, audio_rng=Crand(0xBEEF))
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    session.elapsed_ms = 9876.0
    mocker.patch.object(GameOverUi, "open", return_value=None)

    mode._enter_game_over()

    record = mode._game_over_record
    assert record is not None
    assert record.survival_elapsed_ms == 9876
    assert mode._replay_checkpoint_elapsed_ms() == 9876.0
    assert mode._replay_claimed_stats_elapsed_ms() == 9876
