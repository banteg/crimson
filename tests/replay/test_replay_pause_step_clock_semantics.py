from __future__ import annotations

from types import SimpleNamespace

from crimson.modes import replay_playback_mode
from crimson.replay import Replay, ReplayHeader, ReplayTick


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=replay_playback_mode.GameMode.DEMO, seed=0),
        ticks=[ReplayTick(dt=1 / 60, inputs=[[0.0, 0.0, 0.0, 0.0, 0]]) for _ in range(max(0, int(tick_count)))],
    )


def _set_private(view: replay_playback_mode.ReplayPlaybackMode, name: str, value: object) -> None:
    setattr(view, name, value)


def _stub_world() -> SimpleNamespace:
    return SimpleNamespace(
        ground=None,
        fx_textures=None,
        fx_queue=[],
        fx_queue_rotated=[],
    )


def test_replay_paused_update_does_not_accumulate_clock_debt(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(8))
    _set_private(view, "_runtime", SimpleNamespace(render_resources=_stub_world()))
    view._finished = False
    view._paused = True
    view._dt_accum = 0.375

    advance_calls = 0

    def _advance_runner(**_kwargs) -> None:
        nonlocal advance_calls
        advance_calls += 1

    _set_private(view, "_advance_runner", _advance_runner)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.5)

    assert advance_calls == 0
    assert view._dt_accum == 0.375


def test_replay_step_once_while_paused_advances_exactly_one_tick_and_clears_debt(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(8))
    _set_private(view, "_runtime", SimpleNamespace(render_resources=_stub_world()))
    view._finished = False
    view._paused = True
    view._step_once_pending = True
    view._dt_accum = 0.5
    view._clock.accum = 0.5

    advance_calls = 0

    def _advance_runner(**_kwargs) -> None:
        nonlocal advance_calls
        advance_calls += 1

    _set_private(view, "_advance_runner", _advance_runner)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.25)

    assert advance_calls == 1
    assert view._clock.accum == 0.0
    assert view._step_once_pending is False
    assert view._dt_accum == 0.0


def test_replay_speed_multiplier_scales_dt_only_while_unpaused(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(64))
    _set_private(view, "_runtime", SimpleNamespace(render_resources=_stub_world()))
    view._finished = False
    view._paused = False
    view._speed_index = 3  # 2.0x
    view._dt_accum = 0.0

    advance_dts: list[float] = []

    def _advance_runner(*, dt_seconds: float, **_kwargs) -> None:
        advance_dts.append(float(dt_seconds))
        # Mirror runner clock debt as if ~6 ticks ran for 0.1s at 60 Hz.
        view._dt_accum = 0.0

    _set_private(view, "_advance_runner", _advance_runner)
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.05)
    assert len(advance_dts) == 1
    assert advance_dts[0] == 0.1
    assert view._dt_accum <= (1.0 / 60.0)

    advance_dts.clear()
    view._paused = True
    view.update(0.05)
    assert len(advance_dts) == 0


def test_replay_step_once_eos_is_terminal_not_stall(mocker, replay_playback_view) -> None:
    """When tick_index reaches tick_limit, _advance_runner marks finished without error."""
    view, _console = replay_playback_view
    _set_private(view, "_replay", _replay_with_ticks(2))
    _set_private(view, "_runtime", SimpleNamespace(render_resources=_stub_world()))
    view._finished = False
    view._paused = True
    view._step_once_pending = True
    view._tick_index = 2  # already at tick_limit
    view._max_ticks = None

    _set_private(view, "_driver", SimpleNamespace())
    _set_private(view, "_survival", object())

    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    view.update(0.05)

    assert view._finished is True
    assert view._step_once_pending is False
    assert view._dt_accum == 0.0
