from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=GameMode.DEMO, seed=0),
        inputs=[[[0.0, 0.0, 0.0, 0.0, 0]] for _ in range(max(0, int(tick_count)))],
    )


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

    view._tick_one = fake_tick_one
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

    view._replay = _replay_with_ticks(2)
    view._world = SimpleNamespace(
        players=[SimpleNamespace(health=0.0)],
    )
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    view._on_runner_tick_complete = lambda _tick_index, _tick: False

    @dataclass
    class _FakeRunner:
        next_tick_index: int = 0

        def advance_frame(self, *_args, on_tick_complete, **_kwargs) -> object:
            on_tick_complete(int(self.next_tick_index), object())
            self.next_tick_index += 1
            return object()

    view._tick_runner = _FakeRunner()

    view._tick_one()

    assert view._tick_index == 1
    assert not view._finished


def test_replay_open_uses_driver_tick_runner_builder(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay = Replay(
        header=ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0),
        inputs=[[[0.0, 0.0, 0.0, 0.0, 0]]],
    )
    captured: dict[str, object] = {}

    class _StopOpen(Exception):
        pass

    class _FakeWorld:
        def __init__(self, *args, **kwargs) -> None:
            _ = args, kwargs
            self.world_size = 1000.0
            self.players = []
            self.texture_cache = None
            self.audio = None
            self.audio_bridge = SimpleNamespace(router=None)
            self.render_resources = SimpleNamespace(
                fx_queue=[],
                fx_queue_rotated=[],
            )
            self.sim_world = SimpleNamespace(
                world_state=SimpleNamespace(),
                game_tune_started=False,
            )
            self.state = SimpleNamespace(
                preserve_bugs=False,
                status=None,
                rng=SimpleNamespace(state=0),
            )

        def reset(self, *, seed: int, player_count: int) -> None:
            _ = seed, player_count

        def open(self) -> None:
            return

        def close(self) -> None:
            return

    class _FakeDriver:
        def __init__(self, *_args, **_kwargs) -> None:
            self.survival_session = object()
            self.rush_session = None
            self.quest_session = None

        def open(self) -> None:
            return

        def build_tick_runner(self, *, defer_menu_open: bool | None = None) -> object:
            captured["defer_menu_open"] = defer_menu_open
            raise _StopOpen()

    mocker.patch.object(replay_playback_mode, "load_small_font", return_value=None)
    mocker.patch.object(replay_playback_mode, "load_hud_assets", return_value=None)
    mocker.patch.object(replay_playback_mode, "load_replay_file", return_value=replay)
    mocker.patch.object(replay_playback_mode, "init_audio_state", return_value=None)
    mocker.patch.object(replay_playback_mode, "apply_replay_bootstrap", return_value=None)
    mocker.patch.object(replay_playback_mode, "GameWorld", _FakeWorld)
    mocker.patch.object(replay_playback_mode, "PlaybackDriver", _FakeDriver)

    with pytest.raises(_StopOpen):
        view.open()

    assert captured["defer_menu_open"] is False
