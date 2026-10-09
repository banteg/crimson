from __future__ import annotations

import datetime as dt
import pickle
import random
from collections.abc import Callable
from pathlib import Path

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.replay import Replay, load_replay_file
from crimson.replay.driver.playback_driver import build_runtime_playback_driver
from crimson.replay.driver.prepare import MarkKind, ReplayPreparation
from crimson.screens import replay_viewer
from crimson.screens.actions import Route
from crimson.screens.replay_viewer import ReplayViewer, replay_card
from crimson.sim.clock import PresentationClock
from crimson.sim.commands import PerkPickCommand
from crimson.sim.run_spec import RunSpec
from crimson.world.render_resources import RenderResources
from grim.audio import AudioState
from grim.config import ensure_crimson_cfg
from grim.console import create_console, register_core_cvars
from grim.geom import Vec2
from grim.music import MusicState
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from grim.view import ViewContext
from tests.support.audio import HeadlessAudio
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import record_replay

RECORDED_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "replays"

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

# Held fire: the pistol shoots about every 43 ticks from tick 48 on.
FIRING = player_input(aim=Vec2(700.0, 512.0), fire_down=True)

type OpenViewer = Callable[..., ReplayViewer]


@pytest.fixture
def open_viewer(tmp_path: Path, assets_dir: Path, mocker) -> OpenViewer:
    """Open the viewer on `replay`, prepared whole in this process, with input that reports nothing."""

    def _open(replay: Replay, *, audio: AudioState | None = None) -> ReplayViewer:
        cfg = ensure_crimson_cfg(tmp_path)
        console = create_console(tmp_path, assets_dir=assets_dir)
        register_core_cvars(console, cfg.display.width, cfg.display.height)
        viewer = ReplayViewer(
            ViewContext(assets_dir=assets_dir, preserve_bugs=False),
            replay=replay,
            config=cfg,
            console=console,
            card=replay_card(replay, name="banteg", day=dt.date(2026, 10, 10)),
            audio=audio,
            background=False,
        )
        viewer.open()
        # The world pass renders into GPU render targets; everything drawn over it runs.
        mocker.patch.object(viewer.player.runtime, "draw")
        return viewer

    return _open


def _press(mocker, *keys: int) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key in keys)


def _drawn_texts(viewer: ReplayViewer, mocker) -> list[str]:
    draw_text = mocker.patch.object(replay_viewer, "draw_small_text")
    viewer.draw()
    texts = [call.args[1] for call in draw_text.call_args_list]
    mocker.stop(draw_text)
    return texts


def test_a_seek_lands_on_the_state_straight_play_reaches(open_viewer: OpenViewer) -> None:
    replay = load_replay_file(RECORDED_DIR / "quest-1.1-completed.crd")
    viewer = open_viewer(replay)
    viewer.update(0.0)
    straight = build_runtime_playback_driver(replay, max_ticks=None)
    clock = PresentationClock()
    states: dict[int, tuple[bytes, PresentationClock]] = {}
    for tick in range(len(replay.ticks)):
        clock.advance(straight.step_tick(tick).payload.dt_sim)
        states[tick + 1] = (pickle.dumps(straight.session), msgspec.structs.replace(clock))

    # Backwards and forwards, near a keyframe and far from one.
    for target in random.Random(0).sample(range(1, len(replay.ticks) + 1), 20):
        viewer.seek(target)

        assert viewer.tick == target
        assert (pickle.dumps(viewer.player.driver.session), viewer.player.runtime.presentation) == states[target]


def test_the_pass_in_its_own_process_finds_what_it_finds_here() -> None:
    replay = load_replay_file(RECORDED_DIR / "quest-1.1-completed.crd")
    here = ReplayPreparation(replay, background=False)
    here.poll()
    apart = ReplayPreparation(replay)
    apart.wait()

    assert apart.ended and apart.tick == here.tick == len(replay.ticks)
    assert apart.keys == here.keys
    assert (apart.marks, apart.picks, apart.tunes, apart.bakes.count) == (here.marks, here.picks, here.tunes, here.bakes.count)


def test_the_pick_box_shows_the_menus_offers_once_playback_passes_the_pick(open_viewer: OpenViewer, mocker) -> None:
    replay = load_replay_file(RECORDED_DIR / "quest-2.10-completed.crd")
    picked = [(index, command) for index, tick in enumerate(replay.ticks) for command in tick.commands if isinstance(command, PerkPickCommand)]
    viewer = open_viewer(replay)
    viewer.update(0.0)
    prep = viewer.preparation
    assert prep is not None

    assert [(pick.tick, pick.pick.chosen) for pick in prep.picks] == [(index + 1, command.choice_index) for index, command in picked]
    assert [mark.value for mark in prep.marks if mark.kind == MarkKind.PICK] == [0, 1, 2]
    first = prep.picks[0]
    viewer.seek(first.tick - 2)
    assert viewer.card_pick == -1

    viewer.update(0.1)

    assert viewer.card_pick == 0
    texts = _drawn_texts(viewer, mocker)
    assert f"Level {first.level}" in texts
    assert viewer._perk_name(first, first.pick.chosen) in texts


def test_space_pauses_period_steps_a_tick_and_comma_steps_one_back(open_viewer: OpenViewer, mocker) -> None:
    viewer = open_viewer(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 120))
    viewer.update(0.1)
    at = viewer.tick

    _press(mocker, rl.KeyboardKey.KEY_SPACE)
    viewer.update(0.1)
    assert viewer.paused and viewer.tick == at
    _press(mocker)
    viewer.update(0.1)
    assert viewer.tick == at

    _press(mocker, rl.KeyboardKey.KEY_PERIOD)
    viewer.update(0.0)
    assert viewer.tick == at + 1
    _press(mocker, rl.KeyboardKey.KEY_COMMA)
    viewer.update(0.0)
    assert viewer.tick == at


def test_eight_times_speed_runs_eight_ticks_a_frame(open_viewer: OpenViewer, mocker) -> None:
    viewer = open_viewer(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 400))
    _press(mocker, rl.KeyboardKey.KEY_RIGHT_BRACKET)
    for _ in range(3):
        viewer.update(0.0)
    _press(mocker)

    viewer.update(1.0 / 60.0)

    assert viewer.tick == 8


def test_seeks_are_silent_and_playback_after_them_is_not(open_viewer: OpenViewer, mocker) -> None:
    audio = HeadlessAudio(mocker)
    viewer = open_viewer(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), 400, inputs=FIRING), audio=audio.state)
    first_shot_tick = 48
    while viewer.tick + 6 <= first_shot_tick:
        viewer.update(0.1)
    assert audio.played() == []

    # Right goes 5 seconds on, over the first pistol shots.
    _press(mocker, rl.KeyboardKey.KEY_RIGHT)
    viewer.update(0.0)
    assert viewer.tick > first_shot_tick + 60
    # Left goes back over them.
    _press(mocker, rl.KeyboardKey.KEY_LEFT)
    viewer.update(0.0)
    assert audio.played() == []
    assert viewer.player.runtime.audio_bridge.sfx_enabled

    _press(mocker)
    while not viewer.ended:
        viewer.update(0.1)
    assert SfxId.PISTOL_FIRE in audio.played()


def test_a_seek_forward_bakes_every_tick_it_passes(open_viewer: OpenViewer, mocker) -> None:
    replay = record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), 400, inputs=FIRING)
    viewer = open_viewer(replay)
    viewer.update(0.0)
    # The first shot's decal lands on tick 57; no keyframe lies between it and the seek's start.
    viewer.seek(50)
    consume = mocker.spy(RenderResources, "consume_terrain_fx_batch")

    viewer.seek(59)

    stepped = build_runtime_playback_driver(replay, max_ticks=None)
    fx_by_tick = [stepped.step_tick(tick).payload.presentation.terrain_fx for tick in range(59)]
    expected = [fx for fx in fx_by_tick[50:] if not fx.is_empty()]
    assert expected
    assert [call.args[1] for call in consume.call_args_list] == expected


def test_the_end_says_whether_the_run_played_as_recorded_and_watch_again_starts_over(open_viewer: OpenViewer, mocker) -> None:
    replay = record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 30)
    viewer = open_viewer(replay)
    _press(mocker, rl.KeyboardKey.KEY_END)
    viewer.update(0.016)
    _press(mocker)
    assert viewer.ended
    assert "Played as recorded." in _drawn_texts(viewer, mocker)

    for _ in range(30):
        viewer.update(0.016)
    button = viewer._end_corner() + Vec2(52.0 + 20.0, 250.0 + 10.0)
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(button.x, button.y))
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    viewer.update(0.016)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)
    viewer.update(0.016)
    assert viewer.tick < 5 and not viewer.ended

    doctored = msgspec.structs.replace(replay, result=msgspec.structs.replace(replay.result, kills=replay.result.kills + 1))
    viewer = open_viewer(doctored)
    viewer.update(0.0)
    viewer.seek(viewer.ticks)
    assert "This run played differently." in _drawn_texts(viewer, mocker)


def test_esc_returns_to_the_screen_below_once(open_viewer: OpenViewer, mocker) -> None:
    viewer = open_viewer(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 4))
    _press(mocker, rl.KeyboardKey.KEY_ESCAPE)

    viewer.update(0.016)

    assert viewer.take_action() is Route.BACK
    assert viewer.take_action() is None


def test_the_music_is_the_tune_the_run_has_where_playback_is(open_viewer: OpenViewer, mocker) -> None:
    replay = load_replay_file(RECORDED_DIR / "quest-1.1-completed.crd")
    music = MusicState(ready=True, enabled=True, volume=1.0, active_track="crimson_theme", queue=["gt1_ingame", "gt2_harppen"])
    audio = AudioState(ready=True, music=music, sfx=init_sfx_state(ready=False, enabled=False, volume=1.0, rng=Crand(0)))

    def _play(state: MusicState, track: str, **_kwargs) -> None:
        state.active_track = track

    def _stop(state: MusicState) -> None:
        state.active_track = None

    stop_music = mocker.patch.object(replay_viewer, "stop_music", side_effect=_stop)
    resume_music = mocker.patch.object(replay_viewer, "resume_music", side_effect=_play)
    play_music = mocker.patch.object(replay_viewer, "play_music", side_effect=_play)
    viewer = open_viewer(replay, audio=audio)
    viewer.update(0.0)
    prep = viewer.preparation
    assert prep is not None
    game_tune, completion = prep.tunes
    # The menu's theme stops as the replay starts.
    stop_music.assert_called_once_with(music)

    viewer.seek(game_tune.tick + 10)
    tune = music.queue[game_tune.draw % len(music.queue)]
    resume_music.assert_called_once_with(music, tune)
    # Before the first hit, an in-game tune already playing plays on.
    viewer.seek(game_tune.tick - 10)
    viewer.update(0.0)
    assert music.active_track == tune
    assert stop_music.call_count == 1

    viewer.seek(viewer.ticks)
    viewer.update(0.0)
    assert completion.track == "crimsonquest"
    play_music.assert_called_once_with(music, "crimsonquest", fade_in=True)
