from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.modes import replay_playback_mode
from crimson.modes.replay_playback_mode import ReplayPlaybackMode
from crimson.replay import Replay
from crimson.sim.commands import PerkPickCommand
from crimson.sim.run_spec import RunSpec
from crimson.world.runtime import WorldRuntime
from grim.audio import AudioState
from grim.config import CrimsonConfig, ensure_crimson_cfg
from grim.console import create_console, register_core_cvars
from grim.math import f32
from grim.music import MusicState, MusicTrack
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from grim.view import ViewContext
from tests.support.audio import HeadlessAudio
from tests.support.replay_runner_helpers import record_replay

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

type OpenPlayback = Callable[..., ReplayPlaybackMode]


@pytest.fixture
def open_playback(tmp_path: Path, assets_dir: Path) -> OpenPlayback:
    """Open the replay player on `replay`, optionally with stub audio (no device in tests)."""

    def _open(
        replay: Replay, *, config: CrimsonConfig | None = None, audio: AudioState | None = None,
    ) -> ReplayPlaybackMode:
        cfg = config if config is not None else ensure_crimson_cfg(tmp_path)
        cfg.audio.music_disabled = True
        cfg.audio.sound_disabled = True
        console = create_console(tmp_path, assets_dir=assets_dir)
        register_core_cvars(console, cfg.display.width, cfg.display.height)
        view = ReplayPlaybackMode(
            ViewContext(assets_dir=assets_dir, preserve_bugs=False),
            replay=replay,
            config=cfg,
            console=console,
            audio=audio,
        )
        view.open()
        return view

    return _open


def _runtime(view: ReplayPlaybackMode) -> WorldRuntime:
    return view.runtime


def _draw(view: ReplayPlaybackMode, mocker) -> None:
    # The world pass renders into GPU render targets; everything drawn over it runs.
    mocker.patch.object(_runtime(view), "draw")
    view.draw()


@pytest.mark.parametrize("recorded_gore", [0, 1])
def test_replay_render_uses_recorded_gore_setting(open_playback: OpenPlayback, tmp_path: Path, recorded_gore) -> None:
    viewer_config = ensure_crimson_cfg(tmp_path)
    viewer_config.display.violence_disabled = 1 - recorded_gore
    replay = record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0, violence_disabled=recorded_gore), 1)

    view = open_playback(replay, config=viewer_config)

    frame = _runtime(view).build_render_frame()
    assert frame.config is not None
    assert frame.config.display.violence_disabled == recorded_gore
    assert view.driver.session.world.state.violence_disabled == recorded_gore
    assert viewer_config.display.violence_disabled == 1 - recorded_gore
    assert frame.config is not viewer_config


def test_standalone_replay_audio_queues_the_game_tunes_through_snd_add_game_tune(
    tmp_path: Path, assets_dir: Path, mocker,
) -> None:
    script = tmp_path / "music" / "game_tunes.txt"
    script.parent.mkdir()
    script.write_text("snd_addGameTune gt1_ingame.ogg\nsnd_addGameTune gt2_harppen.ogg\n")
    # Music ready with both tunes already streamed, so no device or music.paq is needed.
    music = MusicState(
        ready=True,
        enabled=True,
        volume=1.0,
        tracks={name: MusicTrack(stream=rl.Music(), track_id=index) for index, name in enumerate(("gt1_ingame", "gt2_harppen"))},
    )
    ready = AudioState(ready=True, music=music, sfx=init_sfx_state(ready=False, enabled=False, volume=1.0, rng=Crand(0x1234)))
    mocker.patch.object(replay_playback_mode, "init_audio_state", return_value=ready)
    console = create_console(tmp_path, assets_dir=assets_dir)

    audio = replay_playback_mode.open_replay_audio(
        ensure_crimson_cfg(tmp_path), ViewContext(assets_dir=assets_dir, preserve_bugs=False), console,
    )

    assert audio is ready
    assert music.queue == ["gt1_ingame", "gt2_harppen"]


def test_playback_plays_at_the_replays_own_pace(open_playback: OpenPlayback) -> None:
    view = open_playback(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 4))

    view.update(2.5 / 60.0)
    assert view.tick_index == 2
    assert not view.finished

    view.update(0.1)
    assert view.finished


def test_quiet_ticks_give_the_sound_effects_back_when_a_tick_raises(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 3))
    audio_bridge = _runtime(view).audio_bridge
    observed_sfx_enabled: list[bool] = []

    def _fail(**_kwargs) -> None:
        observed_sfx_enabled.append(bool(audio_bridge.sfx_enabled))
        raise RuntimeError("quiet test boom")

    # Fault injection: the first quiet tick's audio step fails.
    mocker.patch.object(audio_bridge, "apply_post_plan", side_effect=_fail)

    with pytest.raises(RuntimeError, match="quiet test boom"):
        view.run(1, quiet=True)

    assert observed_sfx_enabled == [False]
    assert audio_bridge.sfx_enabled


def test_closing_gives_back_the_music_and_the_sound_randomness_the_replay_found(
    tmp_path: Path, assets_dir: Path, mocker,
) -> None:
    music = MusicState(ready=True, enabled=True, volume=1.0, active_track="crimson_theme", game_tune_started=True)
    game_rng = Crand(0)
    audio = AudioState(ready=True, music=music, sfx=init_sfx_state(ready=False, enabled=False, volume=1.0, rng=game_rng))
    cfg = ensure_crimson_cfg(tmp_path)
    console = create_console(tmp_path, assets_dir=assets_dir)
    register_core_cvars(console, cfg.display.width, cfg.display.height)
    view = ReplayPlaybackMode(
        ViewContext(assets_dir=assets_dir, preserve_bugs=False),
        replay=record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 2),
        config=cfg,
        console=console,
        audio=audio,
    )
    resume_music = mocker.patch.object(replay_playback_mode, "resume_music")
    view.open()
    assert audio.sfx.rng is not game_rng
    music.game_tune_started = False

    view.close()

    resume_music.assert_called_once_with(music, "crimson_theme")
    assert music.game_tune_started
    assert audio.sfx.rng is game_rng


def test_a_run_that_reaches_its_recorded_result_says_so_and_a_doctored_one_does_not(open_playback: OpenPlayback) -> None:
    replay = record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 4)
    view = open_playback(replay)
    view.update(0.1)
    assert view.finished and view.played_as_recorded

    doctored = msgspec.structs.replace(replay, result=msgspec.structs.replace(replay.result, kills=replay.result.kills + 1))
    view = open_playback(doctored)
    view.update(0.1)
    assert view.finished and view.played_as_recorded is False


def test_a_tick_the_simulation_refuses_stops_playback_there(open_playback: OpenPlayback) -> None:
    replay = record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 3)
    # A pick with no perk pending, which no run could have issued.
    ticks = list(replay.ticks)
    ticks[1] = msgspec.structs.replace(ticks[1], commands=[PerkPickCommand(player_index=0, choice_index=0)])
    view = open_playback(msgspec.structs.replace(replay, ticks=ticks))

    view.update(0.1)

    assert view.finished
    assert view.tick_index == 1
    assert view.ticks == 1
    assert view.stopped_reason == "This run stops playing here (tick 1)"


@pytest.mark.parametrize("fps", [30, 60, 120, 240])
def test_playback_sound_cooldowns_follow_ticks_at_any_refresh_rate(open_playback: OpenPlayback, mocker, fps: int) -> None:
    audio = HeadlessAudio(mocker)
    view = open_playback(record_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 30), audio=audio.state)
    audio.state.sfx.cooldowns[SfxId.FLAMER_FIRE_01] = f32(0.44)

    for _ in range(fps * 2 // 15):
        view.update(1.0 / fps)

    assert view.tick_index == 8
    expected = f32(0.44)
    for _ in range(view.tick_index):
        expected = f32(expected - f32(1.0 / 60.0))
    assert audio.state.sfx.cooldowns[SfxId.FLAMER_FIRE_01] == expected
