from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import crimson.modes.replay_playback_mode as replay_playback_mode
import pytest
from grim.config import CrimsonConfig
from grim.console import ConsoleLog, ConsoleState
from grim.view import ViewContext


def _build_view() -> tuple[replay_playback_mode.ReplayPlaybackMode, ConsoleState]:
    cfg = CrimsonConfig(path=Path("crimson.cfg"), data={})
    console = ConsoleState(base_dir=Path("."), log=ConsoleLog(base_dir=Path(".")))
    view = replay_playback_mode.ReplayPlaybackMode(
        ViewContext(assets_dir=Path("."), preserve_bugs=False),
        replay_path=Path("dummy.crdemo.gz"),
        config=cfg,
        console=console,
    )
    return view, console


def test_replay_playback_registers_snd_add_game_tune_command(monkeypatch) -> None:
    view, console = _build_view()
    music_state = object()
    view._audio = SimpleNamespace(music=music_state)

    loaded: list[tuple[object, Path, str]] = []
    queued: list[tuple[object, str]] = []

    def fake_load_music_track(_music, assets_dir: Path, rel_path: str, *, console: ConsoleState):  # noqa: ARG001
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


def test_replay_playback_load_game_tune_queue_execs_script(monkeypatch) -> None:
    view, console = _build_view()
    view._audio = object()
    calls: list[str] = []

    def fake_exec_line(_self: ConsoleState, line: str) -> None:
        calls.append(line)

    monkeypatch.setattr(ConsoleState, "exec_line", fake_exec_line)

    view._load_game_tune_queue()
    assert calls == ["exec music/game_tunes.txt"]

    view._audio = None
    view._load_game_tune_queue()
    assert calls == ["exec music/game_tunes.txt"]


def test_replay_playback_progress_ratio_and_time_formatting() -> None:
    view, _console = _build_view()
    view._replay = SimpleNamespace(inputs=[0, 0, 0, 0])

    view._tick_index = 2
    assert view._replay_progress_ratio() == 0.5

    view._tick_index = 10
    assert view._replay_progress_ratio() == 1.0

    assert replay_playback_mode.ReplayPlaybackMode._format_time_text(0.0) == "0:00"
    assert replay_playback_mode.ReplayPlaybackMode._format_time_text(65.9) == "1:05"


def test_skip_forward_temporarily_disables_sfx() -> None:
    view, _console = _build_view()
    view._replay = SimpleNamespace(inputs=[0, 0, 0, 0, 0])
    view._world = SimpleNamespace(audio_router=SimpleNamespace(sfx_enabled=True))
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False
    view._dt_accum = 1.0

    sfx_enabled_during_tick: list[bool] = []

    def fake_tick_one() -> None:
        sfx_enabled_during_tick.append(bool(view._world.audio_router.sfx_enabled))
        view._tick_index += 1

    view._tick_one = fake_tick_one  # type: ignore[method-assign]

    view._skip_forward_seconds(2.0 / 60.0)

    assert sfx_enabled_during_tick == [False, False]
    assert bool(view._world.audio_router.sfx_enabled)
    assert view._dt_accum == 0.0


def test_skip_forward_restores_sfx_flag_when_tick_raises() -> None:
    view, _console = _build_view()
    view._replay = SimpleNamespace(inputs=[0, 0, 0])
    view._world = SimpleNamespace(audio_router=SimpleNamespace(sfx_enabled=True))
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False

    sfx_enabled_during_tick: list[bool] = []

    def fake_tick_one() -> None:
        sfx_enabled_during_tick.append(bool(view._world.audio_router.sfx_enabled))
        raise RuntimeError("skip test boom")

    view._tick_one = fake_tick_one  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="skip test boom"):
        view._skip_forward_seconds(1.0 / 60.0)

    assert sfx_enabled_during_tick == [False]
    assert bool(view._world.audio_router.sfx_enabled)


def test_skip_forward_clears_fx_queues_each_tick() -> None:
    view, _console = _build_view()
    replay_inputs = [0, 0, 0, 0]

    class _Queue:
        def __init__(self) -> None:
            self.clear_calls = 0

        def clear(self) -> None:
            self.clear_calls += 1

    fx_queue = _Queue()
    fx_queue_rotated = _Queue()
    view._replay = SimpleNamespace(inputs=replay_inputs)
    view._world = SimpleNamespace(
        audio_router=SimpleNamespace(sfx_enabled=True),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
    )
    view._tick_rate = 60
    view._tick_index = 0
    view._finished = False

    def fake_tick_one() -> None:
        view._tick_index += 1

    view._tick_one = fake_tick_one  # type: ignore[method-assign]

    view._skip_forward_seconds(3.0 / 60.0)

    assert fx_queue.clear_calls == 3
    assert fx_queue_rotated.clear_calls == 3
