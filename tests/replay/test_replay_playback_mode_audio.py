from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Protocol
from unittest.mock import call

import pytest

from crimson.modes import replay_playback_mode
from crimson.quests.level import QuestLevel
from crimson.replay import Replay, ReplayHeader, ReplayTick
from crimson.sim.sessions import QuestSpawnState
from crimson.sim.terrain_fx import TerrainDecalFx, TerrainFxBatch
from crimson.world.sim_world_state import SimWorldState
from grim.color import RGBA
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.builders import FakePlaybackDriver


def _replay_with_ticks(tick_count: int, *, game_mode_id: int = 0) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=replay_playback_mode.GameMode(int(game_mode_id)), seed=0),
        ticks=[ReplayTick(dt=1 / 60, inputs=[[0.0, 0.0, 0.0, 0.0, 0]]) for _ in range(max(0, int(tick_count)))],
    )


def _set_private(view: replay_playback_mode.ReplayPlaybackMode, name: str, value: object) -> None:
    setattr(view, name, value)


@dataclass
class _AudioStub:
    music: object = field(default_factory=object)


@dataclass
class _AudioBridgeStub:
    sfx_enabled: bool = True

    def apply_plan(self, **_kwargs) -> None:
        return None

    def apply_post_plan(self, **_kwargs) -> None:
        return None


class _Clearable(Protocol):
    def clear(self) -> None: ...


@dataclass
class _RenderResourcesStub:
    ground: object | None = None
    fx_textures: object | None = None
    fx_queue: _Clearable = field(default_factory=list)
    fx_queue_rotated: _Clearable = field(default_factory=list)
    consume_terrain_fx_hook: Callable[[TerrainFxBatch], None] | None = None

    def consume_terrain_fx_batch(self, batch: TerrainFxBatch) -> None:
        hook = self.consume_terrain_fx_hook
        if hook is not None:
            hook(batch)


@dataclass
class _RuntimeStub:
    audio_bridge: _AudioBridgeStub
    render_resources: _RenderResourcesStub
    sim_world: SimWorldState = field(default_factory=SimWorldState)

    def sync_audio_bridge_state(self) -> None:
        return None

    def update_camera(self, _dt: float) -> None:
        return None


class _CountingQueue:
    def __init__(self) -> None:
        self.clear_calls = 0

    def clear(self) -> None:
        self.clear_calls += 1


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
    _set_private(view, "_replay", _replay_with_ticks(4))

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

    view._draw_world(draw_aim_indicators=False, entity_alpha=0.5)
    view._draw_ui_text("replay", pos, color, scale=0.8)
    width = view._measure_ui_text_width("replay", scale=0.8)

    runtime.draw.assert_called_once_with(draw_aim_indicators=False, entity_alpha=0.5)
    draw_text.assert_called_once_with(font, "replay", pos, color)
    measure_text.assert_called_once_with(font, "replay")
    assert width == 42.0


def test_skip_forward_temporarily_disables_sfx(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(5))
    audio_bridge = _AudioBridgeStub()
    _set_private(
        view,
        "_runtime",
        _RuntimeStub(
            audio_bridge=audio_bridge,
            render_resources=_RenderResourcesStub(
                ground=None,
                fx_textures=None,
                fx_queue=[],
                fx_queue_rotated=[],
            ),
        ),
    )
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


def test_skip_forward_restores_sfx_flag_when_tick_raises(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(3))
    audio_bridge = _AudioBridgeStub()
    _set_private(
        view,
        "_runtime",
        _RuntimeStub(
            audio_bridge=audio_bridge,
            render_resources=_RenderResourcesStub(
                ground=None,
                fx_textures=None,
                fx_queue=[],
                fx_queue_rotated=[],
            ),
        ),
    )
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


def test_skip_forward_consumes_terrain_fx_each_tick_when_render_ready(replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay_inputs = [0, 0, 0, 0]

    consume_calls = 0

    def _consume_terrain_fx(_batch: TerrainFxBatch) -> None:
        nonlocal consume_calls
        consume_calls += 1

    render_resources = _RenderResourcesStub(
        ground=object(),
        fx_textures=object(),
        consume_terrain_fx_hook=_consume_terrain_fx,
    )
    _set_private(view, "_replay", _replay_with_ticks(len(replay_inputs)))
    _set_private(
        view,
        "_runtime",
        _RuntimeStub(
            audio_bridge=_AudioBridgeStub(),
            render_resources=render_resources,
        ),
    )
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt = 1.0 / 60.0
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=len(replay_inputs), terrain_fx=_terrain_batch()))
    view._max_ticks = None

    view._skip_forward_seconds(3.0 / 60.0)

    assert consume_calls == 3


def test_skip_forward_consumes_terrain_fx_each_tick_when_render_not_ready(replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay_inputs = [0, 0, 0, 0]

    consume_calls = 0

    def _consume_terrain_fx(_batch: TerrainFxBatch) -> None:
        nonlocal consume_calls
        consume_calls += 1

    _set_private(view, "_replay", _replay_with_ticks(len(replay_inputs)))
    _set_private(
        view,
        "_runtime",
        _RuntimeStub(
            audio_bridge=_AudioBridgeStub(),
            render_resources=_RenderResourcesStub(
                ground=None,
                fx_textures=None,
                consume_terrain_fx_hook=_consume_terrain_fx,
            ),
        ),
    )
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt = 1.0 / 60.0
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=len(replay_inputs), terrain_fx=_terrain_batch()))
    view._max_ticks = None

    view._skip_forward_seconds(3.0 / 60.0)

    assert consume_calls == 3


def test_draw_quest_title_uses_shared_overlay_helper(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(
        view,
        "_replay",
        _replay_with_ticks(1, game_mode_id=int(replay_playback_mode.GameMode.QUESTS)),
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
        _replay_with_ticks(1, game_mode_id=int(replay_playback_mode.GameMode.QUESTS)),
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
    _set_private(
        view,
        "_runtime",
        SimpleNamespace(
            render_resources=SimpleNamespace(
                resources=SimpleNamespace(texture=lambda _texture_id: texture),
            ),
            sim_world=SimpleNamespace(
                state=SimpleNamespace(
                    typo=SimpleNamespace(
                        typing=SimpleNamespace(text="reload"),
                    ),
                ),
            ),
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
    overlay = SimpleNamespace(
        prompt_text="move",
        prompt_alpha=1.0,
        hint_text="shoot",
        hint_alpha=0.5,
    )
    _set_private(
        view,
        "_runtime",
        SimpleNamespace(
            sim_world=SimpleNamespace(
                state=SimpleNamespace(tutorial_overlay=overlay),
            ),
        ),
    )

    draw_overlay = mocker.patch.object(replay_playback_mode, "draw_tutorial_overlay_panels")

    view._draw_tutorial_overlays()

    draw_overlay.assert_called_once()
    assert draw_overlay.call_args.args == (overlay,)
