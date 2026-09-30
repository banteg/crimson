from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.modes.rush_mode import RushMode
from crimson.screens.actions import ResultAction, Route, ScoreQuery, ScoreReturnContext, ShowScores
from crimson.sim.sessions import DeterministicSession
from crimson.ui.animation import ui_element_timeline_window
from grim.audio import AudioState
from grim.music import MusicState, MusicTrack
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx import init_sfx_state
from grim.view import ViewContext

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

RESULT_TRACK = "shortie_monk"


def _audio() -> AudioState:
    """Music on and playing, its one track already at volume so requests only switch the active track."""
    return AudioState(
        ready=True,
        music=MusicState(
            ready=True,
            enabled=True,
            volume=1.0,
            tracks={RESULT_TRACK: MusicTrack(stream=rl.Music(), track_id=0, volume=1.0, muted=False)},
        ),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0, rng=Crand(0x1234)),
    )


def _game_over(make_mode_config, assets_dir: Path, *, audio: AudioState | None = None) -> RushMode:
    """A rush run that just died into its game over panel."""
    mode = RushMode(ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(0xBEEF))
    mode.bind_audio(audio, mode.audio_rng)
    mode.open()
    mode._enter_game_over()
    return mode


def _press_result_button(mode: RushMode, action: ResultAction) -> None:
    """Press the game over panel's `action` button and run the panel's close transition out."""
    ui = mode._game_over_ui
    ui._begin_close_transition(action)
    for _ in range(30):
        mode._update_game_over_ui(0.1)
        if ui._close_action is None:
            return
    raise AssertionError("the game over panel never finished closing")


def test_update_game_over_ui_routes_high_scores(make_mode_config, assets_dir) -> None:
    mode = _game_over(make_mode_config, assets_dir)

    _press_result_button(mode, ResultAction.HIGH_SCORES)

    assert mode.take_action() == ShowScores(
        ScoreQuery(mode.default_game_mode_id),
        ScoreReturnContext.capture(mode.config),
    )
    assert mode.close_requested is False


def test_game_over_requests_result_music_until_the_exit_transition(make_mode_config, assets_dir) -> None:
    audio = _audio()
    mode = _game_over(make_mode_config, assets_dir, audio=audio)
    music = audio.music
    assert music.active_track is None

    # The panel asks for the result music every frame, so a track switched away comes back.
    for _ in range(2):
        mode._update_game_over_ui(0.1)
        assert music.active_track == RESULT_TRACK
        music.active_track = None

    mode._game_over_ui._begin_close_transition(ResultAction.MAIN_MENU)
    mode._update_game_over_ui(0.1)
    assert music.active_track is None


def test_update_game_over_ui_routes_main_menu(make_mode_config, assets_dir) -> None:
    mode = _game_over(make_mode_config, assets_dir)

    _press_result_button(mode, ResultAction.MAIN_MENU)

    assert mode.take_action() == Route.MENU
    assert mode.close_requested is True


def test_update_game_over_ui_calls_open_on_play_again(mocker, make_mode_config, assets_dir) -> None:
    mode = _game_over(make_mode_config, assets_dir)
    open_mode = mocker.spy(mode, "open")

    _press_result_button(mode, ResultAction.PLAY_AGAIN)

    open_mode.assert_called_once_with()
    assert mode.take_action() is None
    assert mode._game_over_active is False


def test_open_stops_music_before_run_restart(make_mode_config, assets_dir) -> None:
    audio = _audio()
    mode = _game_over(make_mode_config, assets_dir, audio=audio)
    mode._update_game_over_ui(0.1)
    music = audio.music
    assert music.active_track == RESULT_TRACK

    mode.open()

    assert music.active_track is None
    assert music.tracks[RESULT_TRACK].muted


def test_draw_pause_background_fades_entities_during_game_over_close(mocker, make_mode_config, assets_dir) -> None:
    mode = _game_over(make_mode_config, assets_dir)
    mode._game_over_ui.timeline.closing = True
    mode._game_over_ui.timeline.timeline_ms = int(ui_element_timeline_window(28)[1] * 0.5)

    world_draw = mocker.spy(mode, "_draw_world")

    mode.draw_pause_background()

    world_draw.assert_called_once()
    assert world_draw.call_args.kwargs["entity_alpha"] == 0.5


def test_rush_elapsed_helpers_use_authoritative_session_timer(make_mode_config, assets_dir) -> None:
    mode = RushMode(ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(0xBEEF))
    mode.open()
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    session.elapsed_ms = 9876.0

    mode._enter_game_over()

    record = mode._game_over_record
    assert record is not None
    assert record.survival_elapsed_ms == 9876
    assert mode._replay_checkpoint_elapsed_ms() == 9876.0
