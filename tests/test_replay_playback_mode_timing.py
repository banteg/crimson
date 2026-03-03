from __future__ import annotations

import inspect
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader
from crimson.sim.input import PlayerInput


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=GameMode.DEMO, seed=0),
        inputs=[[[0.0, 0.0, 0.0, 0.0, 0]] for _ in range(max(0, int(tick_count)))],
    )


def _set_private(view, name: str, value: object) -> None:
    setattr(view, name, value)


def test_replay_playback_mode_tick_loop_decrements_accum(mocker, replay_playback_view) -> None:
    # Regression test: a missing `dt_accum -= dt` inside the playback loop
    # can cause the entire replay to run in a single frame (or an infinite loop).
    import crimson.modes.replay_playback_mode as replay_playback_mode
    view, _console = replay_playback_view

    # Prevent key handlers from running.
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)

    calls = 0

    def fake_tick_one() -> None:
        nonlocal calls
        calls += 1
        # If the loop does not decrement accumulated time, it would spin forever.
        if calls > 64:
            raise RuntimeError("playback tick loop did not consume accumulated dt")

    _set_private(view, "_tick_one", fake_tick_one)
    view._finished = False
    view._paused = False
    view._tick_rate = 60
    view._dt = 1.0 / 60.0
    view._dt_accum = 0.0

    view.update(0.05)

    # 0.05s at 60Hz should advance exactly 3 ticks (0.0166.. * 3 == 0.05).
    assert calls == 3


def test_replay_tick_one_does_not_stop_on_player_death(replay_playback_view) -> None:
    view, _console = replay_playback_view

    _set_private(view, "_replay", _replay_with_ticks(2))
    _set_private(
        view,
        "_world",
        SimpleNamespace(
            players=[SimpleNamespace(health=0.0)],
        ),
    )
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    _set_private(view, "_on_runner_tick_complete", lambda _tick_index, _tick: False)

    @dataclass
    class _FakeRunner:
        next_tick_index: int = 0

        def advance_frame(self, *_args, on_tick_complete, **_kwargs) -> object:
            on_tick_complete(int(self.next_tick_index), object())
            self.next_tick_index += 1
            return object()

    _set_private(view, "_tick_runner", _FakeRunner())

    view._tick_one()

    assert view._tick_index == 1
    assert not view._finished


def test_replay_driver_session_forwards_provider_inputs_to_playback_driver(replay_playback_view) -> None:
    view, _console = replay_playback_view
    captured: dict[str, object] = {}

    class _FakeDriver:
        def run_tick(
            self,
            tick_index: int,
            *,
            defer_menu_open: bool | None = None,
            player_inputs: list[PlayerInput] | None = None,
        ) -> object:
            captured["tick_index"] = int(tick_index)
            captured["defer_menu_open"] = bool(defer_menu_open)
            captured["player_inputs"] = list(player_inputs or [])
            return object()

    _set_private(view, "_driver", _FakeDriver())
    _set_private(view, "_survival", object())
    _set_private(view, "_defer_menu_open", True)
    session = replay_playback_mode._ReplayDriverSession(view)
    inputs = [PlayerInput(fire_down=True)]

    session.step_tick(timing=1.0 / 60.0, inputs=inputs)

    assert captured["tick_index"] == 0
    assert captured["defer_menu_open"] is True
    assert captured["player_inputs"] == inputs


def test_replay_driver_tick_fails_fast_when_provider_inputs_missing(replay_playback_view) -> None:
    view, _console = replay_playback_view
    _set_private(
        view,
        "_driver",
        SimpleNamespace(run_tick=lambda *_args, **_kwargs: object()),
    )

    with pytest.raises(RuntimeError, match="provided no inputs"):
        view._run_driver_tick(0, inputs=None)


def test_replay_open_uses_lazy_replay_input_provider_wiring() -> None:
    source = inspect.getsource(replay_playback_mode.ReplayPlaybackMode.open)
    assert "resolve_tick_input=" in source
    assert "tick_inputs=[unpack_tick_inputs(" not in source
