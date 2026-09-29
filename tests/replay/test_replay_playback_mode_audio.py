from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.modes import replay_playback_mode
from crimson.modes.replay_playback_mode import ReplayPlaybackMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.replay import Replay, ReplayRecorder, dump_replay
from crimson.replay.driver.playback_driver import build_runtime_playback_driver
from crimson.replay.input_codec import pack_tick
from crimson.sim.commands import GameCommand, TypoCharCommand
from crimson.sim.input import PlayerInput
from crimson.sim.run_spec import RunSpec
from crimson.world.render_resources import RenderResources
from crimson.world.runtime import WorldRuntime
from grim.assets import TextureId
from grim.audio import AudioState
from grim.config import CrimsonConfig, ensure_crimson_cfg
from grim.console import create_console, register_core_cvars
from grim.fonts.small import measure_small_text_width
from grim.geom import Vec2
from grim.music import MusicState, MusicTrack
from grim.raylib_api import rl
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from grim.view import ViewContext
from tests.support.audio import HeadlessAudio
from tests.support.replay_runner_helpers import finish_replay

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

IDLE = PlayerInput(aim=Vec2(700.0, 512.0))
# Held fire: the pistol shoots about every 43 ticks from tick 48 on.
FIRING = PlayerInput(aim=Vec2(700.0, 512.0), fire_down=True)

type OpenPlayback = Callable[..., ReplayPlaybackMode]


def _record(run: RunSpec, ticks: int, *, inputs: PlayerInput = IDLE, commands: Sequence[Sequence[GameCommand]] = ()) -> Replay:
    """Record `ticks` of `inputs`, with `commands[i]` on tick i, and stamp the simulated result."""
    recorder = ReplayRecorder(run)
    for tick in range(ticks):
        recorder.record(pack_tick([inputs], list(commands[tick]) if tick < len(commands) else []))
    return finish_replay(recorder)


@pytest.fixture
def open_playback(tmp_path: Path, assets_dir: Path) -> OpenPlayback:
    """Open the replay viewer on `replay` saved to disk, with audio off (no device in tests)."""

    def _open(
        replay: Replay, *, config: CrimsonConfig | None = None,
    ) -> ReplayPlaybackMode:
        replay_path = tmp_path / "playback.crd"
        replay_path.write_bytes(dump_replay(replay))
        cfg = config if config is not None else ensure_crimson_cfg(tmp_path)
        cfg.audio.music_disabled = True
        cfg.audio.sound_disabled = True
        console = create_console(tmp_path, assets_dir=assets_dir)
        register_core_cvars(console, cfg.display.width, cfg.display.height)
        view = ReplayPlaybackMode(
            ViewContext(assets_dir=assets_dir, preserve_bugs=False),
            replay_path=replay_path,
            config=cfg,
            console=console,
        )
        view.open()
        return view

    return _open


def _runtime(view: ReplayPlaybackMode) -> WorldRuntime:
    runtime = view._runtime
    assert runtime is not None
    return runtime


def _draw(view: ReplayPlaybackMode, mocker) -> None:
    # The world pass renders into GPU render targets; everything drawn over it runs.
    mocker.patch.object(_runtime(view), "draw")
    view.draw()


@pytest.mark.parametrize("recorded_gore", [0, 1])
def test_replay_render_uses_recorded_gore_setting(open_playback: OpenPlayback, tmp_path: Path, recorded_gore) -> None:
    viewer_config = ensure_crimson_cfg(tmp_path)
    viewer_config.display.violence_disabled = 1 - recorded_gore
    replay = _record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0, violence_disabled=recorded_gore), 1)

    view = open_playback(replay, config=viewer_config)

    frame = _runtime(view).build_render_frame()
    assert frame.config is not None
    assert frame.config.display.violence_disabled == recorded_gore
    assert view._driver is not None
    assert view._driver.session.world.state.violence_disabled == recorded_gore
    assert viewer_config.display.violence_disabled == 1 - recorded_gore
    assert frame.config is not viewer_config


def test_game_tune_script_queues_its_tunes_through_snd_add_game_tune(open_playback: OpenPlayback, tmp_path: Path) -> None:
    script = tmp_path / "music" / "game_tunes.txt"
    script.parent.mkdir()
    script.write_text("snd_addGameTune gt1_ingame.ogg\nsnd_addGameTune gt2_harppen.ogg\n")
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 1))
    # Music ready with both tunes already streamed, so no device or music.paq is needed.
    music = MusicState(
        ready=True,
        enabled=True,
        volume=1.0,
        tracks={name: MusicTrack(stream=rl.Music(), track_id=index) for index, name in enumerate(("gt1_ingame", "gt2_harppen"))},
    )
    view._audio = AudioState(ready=True, music=music, sfx=init_sfx_state(ready=False, enabled=False, volume=1.0))

    view._load_game_tune_queue()

    assert music.queue == ["gt1_ingame", "gt2_harppen"]


def test_replay_progress_ratio_follows_playback(open_playback: OpenPlayback) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 4))

    view.update(2.5 / 60.0)
    assert view.tick_index == 2
    assert view._replay_progress_ratio() == 0.5

    view.update(0.1)
    assert view.finished
    assert view._replay_progress_ratio() == 1.0

    assert ReplayPlaybackMode._format_time_text(0.0) == "0:00"
    assert ReplayPlaybackMode._format_time_text(65.9) == "1:05"


def test_replay_widget_right_aligns_the_total_time(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 150))
    view.update(0.1)
    draw_text = mocker.spy(replay_playback_mode, "draw_small_text")

    _draw(view, mocker)

    texts = {call.args[1]: call.args[2] for call in draw_text.call_args_list}
    assert "REPLAY 1.00x" in texts
    # The 182px widget sits 10px from the right edge of the 640px screen; text keeps 4px inside it.
    total_text = ReplayPlaybackMode._format_time_text(150 / 60)
    font = view._small
    assert font is not None
    assert texts[total_text].x + measure_small_text_width(font, total_text) == 640.0 - 10.0 - 4.0
    assert texts[ReplayPlaybackMode._format_time_text(6 / 60)].x < texts[total_text].x


def test_skip_forward_is_silent_and_playback_after_it_is_not(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), 400, inputs=FIRING))
    # The world's sfx go to a ready audio state whose voices never reach a device.
    audio = HeadlessAudio(mocker)
    runtime = _runtime(view)
    runtime.audio = audio.state
    first_shot_tick = 48
    while view.tick_index + 6 <= first_shot_tick:
        view.update(0.1)
    assert audio.played() == []

    # Right arrow skips forward over the first pistol shot.
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_RIGHT)
    view.update(0.0)
    assert view.tick_index > first_shot_tick
    assert audio.played() == []
    assert runtime.audio_bridge.sfx_enabled

    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    while not view.finished:
        view.update(0.1)
    assert SfxId.PISTOL_FIRE in audio.played()


def test_right_arrow_skips_five_seconds(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 400))
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_RIGHT)

    view.update(0.0)

    assert view.tick_index == 5 * 60


def test_eight_times_speed_runs_eight_ticks_a_frame(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 400))
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_RIGHT_BRACKET)
    for _ in range(3):
        view.update(0.0)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)

    view.update(1.0 / 60.0)

    assert view.tick_index == 8


def test_skip_forward_restores_sfx_flag_when_tick_raises(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0), 3))
    audio_bridge = _runtime(view).audio_bridge
    observed_sfx_enabled: list[bool] = []

    def _fail(**_kwargs) -> None:
        observed_sfx_enabled.append(bool(audio_bridge.sfx_enabled))
        raise RuntimeError("skip test boom")

    # Fault injection: the first skipped tick's audio step fails.
    mocker.patch.object(audio_bridge, "apply_post_plan", side_effect=_fail)

    with pytest.raises(RuntimeError, match="skip test boom"):
        view._skip_forward_seconds(1.0 / 60.0)

    assert observed_sfx_enabled == [False]
    assert audio_bridge.sfx_enabled


def test_skip_forward_applies_every_skipped_ticks_terrain_fx(open_playback: OpenPlayback, mocker) -> None:
    replay = _record(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), 400, inputs=FIRING)
    view = open_playback(replay)
    # The first shot's decal lands on tick 57.
    while view.tick_index + 6 <= 57:
        view.update(0.1)
    skip_from = view.tick_index
    consume = mocker.spy(RenderResources, "consume_terrain_fx_batch")

    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_RIGHT)
    view.update(0.0)

    # The same fx a tick-by-tick run of the skipped ticks produces, in order.
    stepped = build_runtime_playback_driver(replay, max_ticks=None, trace_rng=False)
    fx_by_tick = [stepped.step_tick(tick).payload.presentation.terrain_fx for tick in range(view.tick_index)]
    expected = [fx for fx in fx_by_tick[skip_from:] if not fx.is_empty()]
    assert expected
    assert [call.args[1] for call in consume.call_args_list] == expected


def test_quest_replay_draws_the_title_over_its_spawn_timer(open_playback: OpenPlayback, mocker) -> None:
    level = QuestLevel(1, 1)
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.QUESTS, seed=101, quest_level=level), 60))
    view.update(0.1)
    title_overlay = mocker.spy(replay_playback_mode, "draw_quest_title_timer_overlay")
    banner_overlay = mocker.spy(replay_playback_mode, "draw_quest_complete_banner_overlay")

    _draw(view, mocker)

    quest = quest_by_level(level)
    assert quest is not None
    driver = view._driver
    assert driver is not None
    assert driver.quest_spawn_state is not None
    title_overlay.assert_called_once_with(
        view._grim_mono, quest.title, level.text, timer_ms=driver.quest_spawn_state.spawn_timeline_ms,
    )
    banner_overlay.assert_called_once_with(
        _runtime(view).render_resources.resources.texture(TextureId.UI_TEXT_LEVEL_COMPLETE),
        timer_ms=driver.quest_spawn_state.completion_transition_ms,
    )


def test_typo_replay_draws_the_typed_text_in_the_typing_box(open_playback: OpenPlayback, mocker) -> None:
    typed = [[TypoCharCommand(player_index=0, ch=ch)] for ch in "rel"]
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.TYPO, seed=0xBEEF), 6, commands=typed))
    view.update(0.1)
    typing_box = mocker.spy(replay_playback_mode, "draw_typing_box")

    _draw(view, mocker)

    driver = view._driver
    assert driver is not None
    typing_box.assert_called_once()
    assert typing_box.call_args.args == (_runtime(view).render_resources.resources.texture(TextureId.UI_IND_PANEL),)
    assert typing_box.call_args.kwargs["text"] == "rel"
    assert typing_box.call_args.kwargs["game_time_s"] == driver.elapsed_ms * 0.001


def test_tutorial_replay_draws_the_world_tutorial_overlay(open_playback: OpenPlayback, mocker) -> None:
    view = open_playback(_record(RunSpec(game_mode_id=GameMode.TUTORIAL, seed=0xBEEF), 300))
    # The first tutorial prompt fades in shortly after the start.
    while not (_runtime(view).world.state.tutorial_overlay.prompt_text or view.finished):
        view.update(0.1)
    overlay_panels = mocker.spy(replay_playback_mode, "draw_tutorial_overlay_panels")

    _draw(view, mocker)

    overlay = _runtime(view).world.state.tutorial_overlay
    assert overlay.prompt_text
    overlay_panels.assert_called_once()
    assert overlay_panels.call_args.args == (overlay,)
