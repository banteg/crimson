from __future__ import annotations

from types import SimpleNamespace

from crimson.modes import replay_playback_mode
from tests.support.replay_runner_helpers import idle_replay


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
    _set_private(view, "_replay", idle_replay(8))
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
    _set_private(view, "_replay", idle_replay(8))
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
