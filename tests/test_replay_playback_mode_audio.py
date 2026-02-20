from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call

import pytest

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.replay import Replay, ReplayHeader
from grim.console import ConsoleState


def _replay_with_ticks(tick_count: int, *, game_mode_id: int = 0) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=int(game_mode_id), seed=0),
        inputs=[[[0.0, 0.0, [0.0, 0.0], 0]] for _ in range(max(0, int(tick_count)))],
    )


def _set_private(view: replay_playback_mode.ReplayPlaybackMode, name: str, value: object) -> None:
    setattr(view, name, value)


def test_replay_playback_registers_snd_add_game_tune_command(mocker, replay_playback_view) -> None:
    view, console = replay_playback_view
    music_state = object()
    _set_private(view, "_audio", SimpleNamespace(music=music_state))
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
    _set_private(view, "_audio", object())
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
    world = SimpleNamespace(
        audio_router=SimpleNamespace(sfx_enabled=True),
        fx_queue=[],
        fx_queue_rotated=[],
    )
    _set_private(view, "_world", world)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt_accum = 1.0

    observe_sfx_enabled = SimpleNamespace(mock=None)
    # Keep this as an autospecced call recorder instead of a list spy.
    from unittest.mock import Mock

    observe_sfx_enabled.mock = Mock()

    def fake_tick_one() -> None:
        observe_sfx_enabled.mock(bool(world.audio_router.sfx_enabled))
        view._tick_index += 1

    _set_private(view, "_tick_one", fake_tick_one)

    view._skip_forward_seconds(2.0 / 60.0)

    assert observe_sfx_enabled.mock.call_args_list == [call(False), call(False)]
    assert bool(world.audio_router.sfx_enabled)
    assert view._dt_accum == 0.0


def test_skip_forward_restores_sfx_flag_when_tick_raises(replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(3))
    world = SimpleNamespace(
        audio_router=SimpleNamespace(sfx_enabled=True),
        fx_queue=[],
        fx_queue_rotated=[],
    )
    _set_private(view, "_world", world)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False

    from unittest.mock import Mock

    observe_sfx_enabled = Mock()

    def fake_tick_one() -> None:
        observe_sfx_enabled(bool(world.audio_router.sfx_enabled))
        raise RuntimeError("skip test boom")

    _set_private(view, "_tick_one", fake_tick_one)

    with pytest.raises(RuntimeError, match="skip test boom"):
        view._skip_forward_seconds(1.0 / 60.0)

    assert observe_sfx_enabled.call_args_list == [call(False)]
    assert bool(world.audio_router.sfx_enabled)


def test_skip_forward_clears_fx_queues_each_tick(replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay_inputs = [0, 0, 0, 0]

    class _Queue:
        def __init__(self) -> None:
            self.clear_calls = 0

        def clear(self) -> None:
            self.clear_calls += 1

    fx_queue = _Queue()
    fx_queue_rotated = _Queue()
    _set_private(view, "_replay", _replay_with_ticks(len(replay_inputs)))
    _set_private(
        view,
        "_world",
        SimpleNamespace(
        audio_router=SimpleNamespace(sfx_enabled=True),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        ),
    )
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False

    def fake_tick_one() -> None:
        view._tick_index += 1

    _set_private(view, "_tick_one", fake_tick_one)

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
