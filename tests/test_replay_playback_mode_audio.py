from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from unittest.mock import call

import pytest
from builders import FakePlaybackDriver

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.replay import Replay, ReplayHeader, ReplayTick
from crimson.sim.sessions import QuestSpawnState
from crimson.world.sim_world_state import SimWorldState
from grim.console import ConsoleState


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
class _RouterStub:
    sfx_enabled: bool = True

    def play_sfx(self, _key: str) -> None:
        return None


@dataclass
class _AudioBridgeStub:
    router: _RouterStub = field(default_factory=_RouterStub)


class _Clearable(Protocol):
    def clear(self) -> None: ...


@dataclass
class _RenderResourcesStub:
    ground: object | None = None
    fx_textures: object | None = None
    fx_queue: _Clearable = field(default_factory=list)
    fx_queue_rotated: _Clearable = field(default_factory=list)
    bake_fx_queues_hook: Callable[[], None] | None = None

    def bake_fx_queues(self) -> None:
        hook = self.bake_fx_queues_hook
        if hook is not None:
            hook()
            return
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()


@dataclass
class _RuntimeStub:
    audio_bridge: _AudioBridgeStub
    render_resources: _RenderResourcesStub
    sim_world: SimWorldState = field(default_factory=SimWorldState)


class _CountingQueue:
    def __init__(self) -> None:
        self.clear_calls = 0

    def clear(self) -> None:
        self.clear_calls += 1


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

    load_music_track.assert_called_once_with(music_state, Path("."), "music/gt1_ingame.ogg", console=console)
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


def test_skip_forward_temporarily_disables_sfx(replay_playback_view) -> None:
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

    observed_sfx_enabled: list[bool] = []
    _set_private(
        view,
        "_on_runner_tick_complete",
        lambda *_args, **_kwargs: observed_sfx_enabled.append(bool(audio_bridge.router.sfx_enabled)) or False,
    )
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=5))
    view._max_ticks = None

    view._skip_forward_seconds(2.0 / 60.0)

    assert observed_sfx_enabled == [False, False]
    assert bool(audio_bridge.router.sfx_enabled)
    assert view._dt_accum == 0.0


def test_skip_forward_restores_sfx_flag_when_tick_raises(replay_playback_view) -> None:
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

    def _on_runner_tick_complete(*_args, **_kwargs) -> bool:
        observed_sfx_enabled.append(bool(audio_bridge.router.sfx_enabled))
        raise RuntimeError("skip test boom")

    _set_private(view, "_on_runner_tick_complete", _on_runner_tick_complete)
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=3))
    view._max_ticks = None

    with pytest.raises(RuntimeError, match="skip test boom"):
        view._skip_forward_seconds(1.0 / 60.0)

    assert observed_sfx_enabled == [False]
    assert bool(audio_bridge.router.sfx_enabled)


def test_skip_forward_bakes_fx_queues_each_tick_when_render_ready(replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay_inputs = [0, 0, 0, 0]

    fx_queue = _CountingQueue()
    fx_queue_rotated = _CountingQueue()
    bake_calls = 0

    def _bake_fx_queues() -> None:
        nonlocal bake_calls
        bake_calls += 1
        fx_queue.clear()
        fx_queue_rotated.clear()

    render_resources = _RenderResourcesStub(
        ground=object(),
        fx_textures=object(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        bake_fx_queues_hook=_bake_fx_queues,
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
    _set_private(view, "_on_runner_tick_complete", lambda *_args, **_kwargs: False)
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=len(replay_inputs)))
    view._max_ticks = None

    view._skip_forward_seconds(3.0 / 60.0)

    assert bake_calls == 3
    assert fx_queue.clear_calls == 3
    assert fx_queue_rotated.clear_calls == 3


def test_skip_forward_clears_fx_queues_each_tick_when_render_not_ready(replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay_inputs = [0, 0, 0, 0]

    fx_queue = _CountingQueue()
    fx_queue_rotated = _CountingQueue()
    _set_private(view, "_replay", _replay_with_ticks(len(replay_inputs)))
    _set_private(
        view,
        "_runtime",
        _RuntimeStub(
            audio_bridge=_AudioBridgeStub(),
            render_resources=_RenderResourcesStub(
                ground=None,
                fx_textures=None,
                fx_queue=fx_queue,
                fx_queue_rotated=fx_queue_rotated,
            ),
        ),
    )
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt = 1.0 / 60.0
    _set_private(view, "_on_runner_tick_complete", lambda *_args, **_kwargs: False)
    _set_private(view, "_driver", FakePlaybackDriver(tick_limit=len(replay_inputs)))
    view._max_ticks = None

    view._skip_forward_seconds(3.0 / 60.0)

    assert fx_queue.clear_calls == 3
    assert fx_queue_rotated.clear_calls == 3


def test_draw_quest_title_uses_shared_overlay_helper(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(
        view,
        "_replay",
        _replay_with_ticks(1, game_mode_id=int(replay_playback_mode.GameMode.QUESTS)),
    )
    _set_private(view, "_grim_mono", object())
    _set_private(view, "_quest_title", "Castle Keep")
    _set_private(view, "_quest_level", "4.7")
    view._quest_name_timer_ms = 123.0

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
    _set_private(view, "_quest_complete_texture", texture)
    view._quest_completion_transition_ms = 777.0

    draw_overlay = mocker.patch.object(replay_playback_mode, "draw_quest_complete_banner_overlay")

    view._draw_quest_complete_banner()

    draw_overlay.assert_called_once_with(texture, timer_ms=777.0)


def test_post_apply_reaction_reads_quest_runtime_from_driver(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    audio_bridge = _AudioBridgeStub()
    runtime = _RuntimeStub(
        audio_bridge=audio_bridge,
        render_resources=_RenderResourcesStub(
            ground=None,
            fx_textures=None,
            fx_queue=[],
            fx_queue_rotated=[],
        ),
    )
    _set_private(view, "_runtime", runtime)
    _set_private(
        view,
        "_driver",
        FakePlaybackDriver(
            tick_limit=1,
            quest_spawn_state=QuestSpawnState(
                spawn_timeline_ms=444.0,
                completion_transition_ms=222.0,
                play_hit_sfx=True,
                play_completion_music=True,
            ),
        ),
    )
    _set_private(view, "_audio", type("AudioStateStub", (), {"music": type("MusicStub", (), {"playbacks": {}})()})())
    play_sfx = mocker.patch.object(audio_bridge.router, "play_sfx")
    play_music = mocker.patch.object(replay_playback_mode, "play_music")

    reaction = view._build_post_apply_reaction(
        tick_result=FakePlaybackDriver(tick_limit=1).step_tick(0),
    )
    view._apply_post_apply_reaction(reaction)

    assert view._quest_spawn_timeline_ms == 444.0
    assert view._quest_name_timer_ms == pytest.approx(1000.0 / 60.0)
    assert view._quest_completion_transition_ms == 222.0
    play_sfx.assert_called_once_with("sfx_questhit")
    play_music.assert_called_once()


def test_post_apply_reaction_plays_recorded_bonus_sfx(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
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
    play_sfx = mocker.patch.object(audio_bridge.router, "play_sfx")

    reaction = view._build_post_apply_reaction(
        tick_result=FakePlaybackDriver(
            tick_limit=1,
            post_apply_sfx_keys=("sfx_ui_bonus",),
        ).step_tick(0),
    )
    view._apply_post_apply_reaction(reaction)

    play_sfx.assert_called_once_with("sfx_ui_bonus")
