from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.replay import Replay, ReplayHeader
from crimson.sim.input_providers import ReplayEndOfStream


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=replay_playback_mode.GameMode.DEMO, seed=0),
        inputs=[[[0.0, 0.0, 0.0, 0.0, 0]] for _ in range(max(0, int(tick_count)))],
    )


def _set_private(view: replay_playback_mode.ReplayPlaybackMode, name: str, value: object) -> None:
    setattr(view, name, value)


def test_replay_paused_update_does_not_accumulate_clock_debt(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(8))
    _set_private(view, "_world", SimpleNamespace(ground=None))
    view._finished = False
    view._paused = True
    view._dt_accum = 0.375

    tick_calls = 0

    def _tick_one() -> None:
        nonlocal tick_calls
        tick_calls += 1

    _set_private(view, "_tick_one", _tick_one)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.5)

    assert tick_calls == 0
    assert view._dt_accum == 0.375


def test_replay_step_once_while_paused_advances_exactly_one_tick_and_clears_debt(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(8))
    _set_private(view, "_world", SimpleNamespace(ground=None))
    view._finished = False
    view._paused = True
    view._step_once_pending = True
    view._dt_accum = 0.5

    tick_calls = 0

    def _tick_one() -> None:
        nonlocal tick_calls
        tick_calls += 1

    @dataclass
    class _FakeRunner:
        reset_calls: int = 0

        def reset_clock(self) -> None:
            self.reset_calls += 1

    runner = _FakeRunner()
    _set_private(view, "_tick_runner", runner)
    _set_private(view, "_tick_one", _tick_one)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.25)

    assert tick_calls == 1
    assert runner.reset_calls == 2
    assert view._step_once_pending is False
    assert view._dt_accum == 0.0


def test_replay_speed_multiplier_scales_dt_only_while_unpaused(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(64))
    _set_private(view, "_world", SimpleNamespace(ground=None))
    view._finished = False
    view._paused = False
    view._speed_index = 3  # 2.0x
    view._dt_accum = 0.0

    tick_calls = 0

    def _tick_one() -> None:
        nonlocal tick_calls
        tick_calls += 1

    _set_private(view, "_tick_one", _tick_one)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.05)
    assert tick_calls == 6
    assert view._dt_accum <= (1.0 / 60.0)

    tick_calls = 0
    view._paused = True
    view.update(0.05)
    assert tick_calls == 0


def test_replay_step_once_eos_is_terminal_not_stall(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(2))
    _set_private(view, "_world", SimpleNamespace(ground=None))
    view._finished = False
    view._paused = True
    view._step_once_pending = True
    view._tick_index = 1

    apply_terminal_calls: list[int] = []
    _set_private(
        view,
        "_driver",
        SimpleNamespace(apply_terminal_events=lambda tick_index: apply_terminal_calls.append(int(tick_index))),
    )
    _set_private(view, "_survival", object())

    @dataclass
    class _EosRunner:
        next_tick_index: int = 2
        reset_calls: int = 0

        def reset_clock(self) -> None:
            self.reset_calls += 1

        def advance_frame(self, *_args, **_kwargs) -> None:
            raise ReplayEndOfStream("eos")

    runner = _EosRunner()
    _set_private(view, "_tick_runner", runner)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.05)

    assert view._finished is True
    assert view._tick_index == 2
    assert view._step_once_pending is False
    assert view._dt_accum == 0.0
    assert apply_terminal_calls == [2]
