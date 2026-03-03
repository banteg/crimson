from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader


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
