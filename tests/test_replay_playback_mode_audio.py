from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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


def test_replay_playback_registers_snd_add_game_tune_command(monkeypatch, replay_playback_view) -> None:
    view, console = replay_playback_view
    music_state = object()
    _set_private(view, "_audio", SimpleNamespace(music=music_state))

    loaded: list[tuple[object, Path, str]] = []
    queued: list[tuple[object, str]] = []

    def fake_load_music_track(_music, assets_dir: Path, rel_path: str, *, console: ConsoleState):
        loaded.append((_music, assets_dir, rel_path))
        return "gt1_ingame", 7

    def fake_queue_track(_music, track_key: str) -> None:
        queued.append((_music, track_key))

    monkeypatch.setattr(replay_playback_mode.grim_music, "load_music_track", fake_load_music_track)
    monkeypatch.setattr(replay_playback_mode.grim_music, "queue_track", fake_queue_track)

    view._register_replay_audio_commands()
    handler = console.commands.get("snd_addGameTune")
    assert handler is not None
    handler(["gt1_ingame.ogg"])

    assert loaded == [(music_state, Path("."), "music/gt1_ingame.ogg")]
    assert queued == [(music_state, "gt1_ingame")]


def test_replay_playback_load_game_tune_queue_execs_script(monkeypatch, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_audio", object())
    calls: list[str] = []

    def fake_exec_line(_self: ConsoleState, line: str) -> None:
        calls.append(line)

    monkeypatch.setattr(ConsoleState, "exec_line", fake_exec_line)

    view._load_game_tune_queue()
    assert calls == ["exec music/game_tunes.txt"]

    _set_private(view, "_audio", None)
    view._load_game_tune_queue()
    assert calls == ["exec music/game_tunes.txt"]


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
    world = SimpleNamespace(audio_router=SimpleNamespace(sfx_enabled=True))
    _set_private(view, "_world", world)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt_accum = 1.0

    sfx_enabled_during_tick: list[bool] = []

    def fake_tick_one() -> None:
        sfx_enabled_during_tick.append(bool(world.audio_router.sfx_enabled))
        view._tick_index += 1

    _set_private(view, "_tick_one", fake_tick_one)

    view._skip_forward_seconds(2.0 / 60.0)

    assert sfx_enabled_during_tick == [False, False]
    assert bool(world.audio_router.sfx_enabled)
    assert view._dt_accum == 0.0


def test_skip_forward_restores_sfx_flag_when_tick_raises(replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(3))
    world = SimpleNamespace(audio_router=SimpleNamespace(sfx_enabled=True))
    _set_private(view, "_world", world)
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False

    sfx_enabled_during_tick: list[bool] = []

    def fake_tick_one() -> None:
        sfx_enabled_during_tick.append(bool(world.audio_router.sfx_enabled))
        raise RuntimeError("skip test boom")

    _set_private(view, "_tick_one", fake_tick_one)

    with pytest.raises(RuntimeError, match="skip test boom"):
        view._skip_forward_seconds(1.0 / 60.0)

    assert sfx_enabled_during_tick == [False]
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


def test_draw_quest_title_uses_shared_overlay_helper(monkeypatch, replay_playback_view) -> None:
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

    calls: list[tuple[object, str, str, float]] = []

    def fake_draw(font, title: str, number: str, *, timer_ms: float) -> None:
        calls.append((font, title, number, timer_ms))

    monkeypatch.setattr(replay_playback_mode, "draw_quest_title_timer_overlay", fake_draw)

    view._draw_quest_title()

    assert calls == [(view._grim_mono, "Castle Keep", "4.7", 123.0)]


def test_draw_quest_complete_banner_uses_shared_overlay_helper(monkeypatch, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(
        view,
        "_replay",
        _replay_with_ticks(1, game_mode_id=int(replay_playback_mode.GameMode.QUESTS)),
    )
    texture = object()
    _set_private(view, "_quest_complete_texture", texture)
    view._quest_completion_transition_ms = 777.0

    calls: list[tuple[object, float]] = []

    def fake_draw(tex, *, timer_ms: float) -> None:
        calls.append((tex, timer_ms))

    monkeypatch.setattr(replay_playback_mode, "draw_quest_complete_banner_overlay", fake_draw)

    view._draw_quest_complete_banner()

    assert calls == [(texture, 777.0)]
