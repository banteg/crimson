from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call

import pytest

from crimson.game_modes import GameMode
from crimson.modes import replay_playback_mode
from crimson.quests.level import QuestLevel
from crimson.sim.run_spec import RunSpec
from crimson.sim.sessions import QuestSpawnState
from crimson.sim.terrain_fx import TerrainDecalFx, TerrainFxBatch
from crimson.tutorial.state import TutorialOverlayState
from crimson.world import WorldRuntime
from crimson.world.render_resources import RenderResources
from grim.color import RGBA
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from tests.support.builders import FakePlaybackDriver
from tests.support.builders.session import make_world
from tests.support.replay_runner_helpers import idle_replay


def _set_private(view: replay_playback_mode.ReplayPlaybackMode, name: str, value: object) -> None:
    setattr(view, name, value)


@pytest.mark.usefixtures("headless_resources")
@pytest.mark.parametrize("recorded_gore", [0, 1])
def test_replay_render_uses_recorded_gore_setting(mocker, replay_playback_view, recorded_gore) -> None:
    view, _console = replay_playback_view
    viewer_config = view._config
    viewer_config.display.violence_disabled = 1 - recorded_gore
    viewer_config.audio.music_disabled = True
    viewer_config.audio.sound_disabled = True
    replay = idle_replay(0, run=RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0, violence_disabled=recorded_gore))
    mocker.patch.object(replay_playback_mode, "load_replay_file", return_value=replay)

    view.open()

    assert view._runtime is not None
    frame = view._runtime.build_render_frame()
    assert frame.config is not None
    assert frame.config.display.violence_disabled == recorded_gore
    assert view._driver is not None
    assert view._driver.session.world.state.violence_disabled == recorded_gore
    assert viewer_config.display.violence_disabled == 1 - recorded_gore
    assert frame.config is not viewer_config


@dataclass
class _AudioStub:
    music: object = field(default_factory=object)


def _runtime(assets_dir: Path) -> WorldRuntime:
    return WorldRuntime(assets_dir=assets_dir, audio_rng=Crand(0))


def _terrain_batch() -> TerrainFxBatch:
    return TerrainFxBatch(
        decals=(
            TerrainDecalFx(
                effect_id=3,
                rotation=0.0,
                pos=Vec2(32.0, 48.0),
                width=24.0,
                height=24.0,
                color=RGBA(1.0, 1.0, 1.0, 1.0),
            ),
        ),
    )


def test_replay_playback_registers_snd_add_game_tune_command(mocker, replay_playback_view) -> None:
    view, console = replay_playback_view
    music_state = object()
    _set_private(view, "_audio", _AudioStub(music=music_state))
    load_music_track = mocker.patch.object(
        replay_playback_mode.grim_music,
        "load_music_track",
        return_value=("gt1_ingame", 7),
    )
    queue_track = mocker.patch.object(replay_playback_mode.grim_music, "queue_track")

    view._register_replay_audio_commands()
    handler = console.commands.get("snd_addGameTune")
    assert handler is not None
    handler(["gt1_ingame.ogg"])

    load_music_track.assert_called_once_with(music_state, view._ctx.assets_dir, "music/gt1_ingame.ogg", console=console)
    queue_track.assert_called_once_with(music_state, "gt1_ingame")


def test_replay_playback_load_game_tune_queue_execs_script(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_audio", _AudioStub())
    exec_line = mocker.patch.object(ConsoleState, "exec_line")

    view._load_game_tune_queue()
    assert exec_line.call_args_list == [call("exec music/game_tunes.txt")]

    _set_private(view, "_audio", None)
    view._load_game_tune_queue()
    assert exec_line.call_args_list == [call("exec music/game_tunes.txt")]


def test_replay_playback_progress_ratio_and_time_formatting(replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", idle_replay(4))

    view._tick_index = 2
    assert view._replay_progress_ratio() == 0.5

    view._tick_index = 10
    assert view._replay_progress_ratio() == 1.0

    assert replay_playback_mode.ReplayPlaybackMode._format_time_text(0.0) == "0:00"
    assert replay_playback_mode.ReplayPlaybackMode._format_time_text(65.9) == "1:05"


def test_replay_playback_helpers_delegate_to_runtime_and_small_font(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    draw_text = mocker.patch.object(replay_playback_mode, "draw_small_text")
    measure_text = mocker.patch.object(replay_playback_mode, "measure_small_text_width", return_value=42.0)
    color = rl.Color(20, 30, 40, 255)
    pos = Vec2(12.0, 34.0)
    font = object()
    runtime = SimpleNamespace(draw=mocker.Mock())
    _set_private(view, "_small", font)
    _set_private(view, "_runtime", runtime)

    view._draw_world(entity_alpha=0.5)
    view._draw_ui_text("replay", pos, color)
    width = view._measure_ui_text_width("replay")

    runtime.draw.assert_called_once_with(entity_alpha=0.5)
    draw_text.assert_called_once_with(font, "replay", pos, color)
    measure_text.assert_called_once_with(font, "replay")
    assert width == 42.0


def test_skip_forward_temporarily_disables_sfx(mocker, replay_playback_view, assets_dir: Path) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", idle_replay(5))
    runtime = _runtime(assets_dir)
    audio_bridge = runtime.audio_bridge
    _set_private(view, "_runtime", runtime)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt_accum = 1.0
    view._dt = 1.0 / 60.0

    def check_muted(**_kwargs) -> None:
        assert not audio_bridge.sfx_enabled

    apply_post_plan = mocker.patch.object(
        audio_bridge,
        "apply_post_plan",
        side_effect=check_muted,
    )
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=5))
    view._max_ticks = None

    view._skip_forward_seconds(2.0 / 60.0)

    assert apply_post_plan.call_count == 2
    assert bool(audio_bridge.sfx_enabled)
    assert view._dt_accum == 0.0


def test_skip_forward_restores_sfx_flag_when_tick_raises(mocker, replay_playback_view, assets_dir: Path) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", idle_replay(3))
    runtime = _runtime(assets_dir)
    audio_bridge = runtime.audio_bridge
    _set_private(view, "_runtime", runtime)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt = 1.0 / 60.0

    observed_sfx_enabled: list[bool] = []

    def _apply_post_plan(**_kwargs) -> None:
        observed_sfx_enabled.append(bool(audio_bridge.sfx_enabled))
        raise RuntimeError("skip test boom")

    mocker.patch.object(audio_bridge, "apply_post_plan", side_effect=_apply_post_plan)
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=3))
    view._max_ticks = None

    with pytest.raises(RuntimeError, match="skip test boom"):
        view._skip_forward_seconds(1.0 / 60.0)

    assert observed_sfx_enabled == [False]
    assert bool(audio_bridge.sfx_enabled)


def test_skip_forward_consumes_terrain_fx_each_tick(mocker, replay_playback_view, assets_dir: Path) -> None:
    view, _console = replay_playback_view
    replay_inputs = [0, 0, 0, 0]

    runtime = _runtime(assets_dir)
    consume = mocker.patch.object(RenderResources, "consume_terrain_fx_batch")
    _set_private(view, "_replay", idle_replay(len(replay_inputs)))
    _set_private(view, "_runtime", runtime)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt = 1.0 / 60.0
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=len(replay_inputs), terrain_fx=_terrain_batch()))
    view._max_ticks = None

    view._skip_forward_seconds(3.0 / 60.0)

    assert consume.call_count == 3


def test_draw_quest_title_uses_shared_overlay_helper(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(
        view,
        "_replay",
        idle_replay(1, run=RunSpec(game_mode_id=GameMode.QUESTS, seed=0, quest_level=QuestLevel(1, 1))),
    )
    _set_private(view, "_grim_mono", object())
    _set_private(view, "_quest_title", "Castle Keep")
    _set_private(view, "_quest_level", QuestLevel(4, 7))
    _set_private(
        view,
        "_driver",
        FakePlaybackDriver(
            tick_limit=1,
            quest_spawn_state=QuestSpawnState(spawn_timeline_ms=123.0),
        ),
    )

    draw_overlay = mocker.patch.object(replay_playback_mode, "draw_quest_title_timer_overlay")

    view._draw_quest_title()

    draw_overlay.assert_called_once_with(view._grim_mono, "Castle Keep", "4.7", timer_ms=123.0)


def test_draw_quest_complete_banner_uses_shared_overlay_helper(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(
        view,
        "_replay",
        idle_replay(1, run=RunSpec(game_mode_id=GameMode.QUESTS, seed=0, quest_level=QuestLevel(1, 1))),
    )
    texture = object()
    _set_private(
        view,
        "_runtime",
        SimpleNamespace(
            render_resources=SimpleNamespace(
                resources=SimpleNamespace(texture=lambda _texture_id: texture),
            ),
        ),
    )
    _set_private(
        view,
        "_driver",
        FakePlaybackDriver(
            tick_limit=1,
            quest_spawn_state=QuestSpawnState(completion_transition_ms=777.0),
        ),
    )

    draw_overlay = mocker.patch.object(replay_playback_mode, "draw_quest_complete_banner_overlay")

    view._draw_quest_complete_banner()

    draw_overlay.assert_called_once_with(texture, timer_ms=777.0)


def test_draw_typing_box_uses_shared_overlay_helper_and_driver_elapsed_ms(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    texture = object()
    world = make_world()
    world.state.typo.typing.text = "reload"
    _set_private(
        view,
        "_runtime",
        SimpleNamespace(
            render_resources=SimpleNamespace(
                resources=SimpleNamespace(texture=lambda _texture_id: texture),
            ),
            world=world,
        ),
    )
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=1, elapsed_ms=250.0))

    draw_overlay = mocker.patch.object(replay_playback_mode, "draw_typing_box")

    view._draw_typing_box()

    draw_overlay.assert_called_once()
    assert draw_overlay.call_args.args == (texture,)
    assert draw_overlay.call_args.kwargs["text"] == "reload"
    assert draw_overlay.call_args.kwargs["cursor_pulse_time"] == 0.25


def test_draw_tutorial_overlays_uses_shared_overlay_helper(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    world = make_world()
    overlay = TutorialOverlayState(prompt_text="move", prompt_alpha=1.0, hint_text="shoot", hint_alpha=0.5)
    world.state.tutorial_overlay = overlay
    _set_private(view, "_runtime", SimpleNamespace(world=world))

    draw_overlay = mocker.patch.object(replay_playback_mode, "draw_tutorial_overlay_panels")

    view._draw_tutorial_overlays()

    draw_overlay.assert_called_once()
    assert draw_overlay.call_args.args == (overlay,)
