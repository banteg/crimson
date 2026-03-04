from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader
from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import InputStatus
from crimson.sim.tick_runner import TickBatchResult


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=GameMode.DEMO, seed=0),
        inputs=[[[0.0, 0.0, 0.0, 0.0, 0]] for _ in range(max(0, int(tick_count)))],
    )


def test_replay_playback_mode_tick_loop_decrements_accum(mocker, replay_playback_view) -> None:
    # Regression test: frame delta should be consumed by runner clock debt and
    # advance the expected number of ticks in one `advance_frame` call.
    import crimson.modes.replay_playback_mode as replay_playback_mode
    view, _console = replay_playback_view

    # Prevent key handlers from running.
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)
    view._replay = _replay_with_ticks(16)
    view._render_resources = SimpleNamespace(
        ground=None,
        fx_textures=None,
        fx_queue=[],
        fx_queue_rotated=[],
    )
    view._finished = False
    view._paused = False
    view._tick_index = 0
    view._tick_rate = 60
    view._dt = 1.0 / 60.0
    view._dt_accum = 0.0
    view._on_runner_tick_complete = lambda _tick_index, _tick: False

    @dataclass
    class _FakeRunner:
        frame_count: int = 0

        def begin_frame(self, frame_ctx) -> None:
            _ = frame_ctx
            self.frame_count += 1

        def advance_ticks(self, *, start_tick: int, ticks_requested: int, tick_dt: float) -> object:
            _ = tick_dt
            ticks = max(0, int(ticks_requested))
            rows = [
                TickResult(
                    tick_index=int(start_tick + i),
                    command_hash=f"h{int(start_tick + i)}",
                    dt_sim=1.0 / 60.0,
                    payload=object(),
                )
                for i in range(int(ticks))
            ]
            return TickBatchResult(
                ticks_completed=int(ticks),
                batch_status=InputStatus.READY,
                next_tick_index=int(start_tick) + int(ticks),
                completed_results=rows,
            )

    view._tick_runner = _FakeRunner()

    view.update(0.05)

    # 0.05s at 60Hz should advance exactly 3 ticks (0.0166.. * 3 == 0.05).
    assert view._tick_index == 3
    assert view._dt_accum <= (1.0 / 60.0)


def test_replay_runner_advance_does_not_stop_on_player_death(replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._render_resources = SimpleNamespace(
        ground=None,
        fx_textures=None,
        fx_queue=[],
        fx_queue_rotated=[],
    )
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    view._on_runner_tick_complete = lambda _tick_index, _tick: False

    @dataclass
    class _FakeRunner:
        frame_count: int = 0

        def begin_frame(self, frame_ctx) -> None:
            _ = frame_ctx
            self.frame_count += 1

        def advance_ticks(self, *, start_tick: int, ticks_requested: int, tick_dt: float) -> object:
            _ = ticks_requested, tick_dt
            tick_index = int(start_tick)
            return TickBatchResult(
                ticks_completed=1,
                batch_status=InputStatus.READY,
                next_tick_index=int(start_tick) + 1,
                completed_results=[
                    TickResult(
                        tick_index=tick_index,
                        command_hash=f"h{tick_index}",
                        dt_sim=1.0 / 60.0,
                        payload=object(),
                    ),
                ],
            )

    view._tick_runner = _FakeRunner()

    view._advance_runner(
        dt_seconds=float(view._dt),
        max_ticks=1,
    )

    assert view._tick_index == 1
    assert not view._finished


def test_replay_runner_eos_applies_partial_completed_results(replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._render_resources = SimpleNamespace(
        ground=None,
        fx_textures=None,
        fx_queue=[],
        fx_queue_rotated=[],
    )
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    applied_ticks: list[int] = []
    view._on_runner_tick_complete = lambda tick_index, _tick: applied_ticks.append(int(tick_index)) or False

    @dataclass
    class _FakeRunner:
        frame_count: int = 0

        def begin_frame(self, frame_ctx) -> None:
            _ = frame_ctx
            self.frame_count += 1

        def advance_ticks(self, *, start_tick: int, ticks_requested: int, tick_dt: float) -> object:
            _ = ticks_requested, tick_dt
            return TickBatchResult(
                ticks_completed=2,
                batch_status=InputStatus.EOS,
                next_tick_index=int(start_tick) + 2,
                completed_results=[
                    TickResult(
                        tick_index=int(start_tick),
                        command_hash="h0",
                        dt_sim=1.0 / 60.0,
                        payload=object(),
                    ),
                    TickResult(
                        tick_index=int(start_tick) + 1,
                        command_hash="h1",
                        dt_sim=1.0 / 60.0,
                        payload=object(),
                    ),
                ],
            )

    view._tick_runner = _FakeRunner()

    view._advance_runner(
        dt_seconds=float(view._dt),
        max_ticks=2,
    )

    assert applied_ticks == [0, 1]
    assert view._tick_index == 2
    assert view._finished is True


def test_replay_open_uses_driver_tick_runner_builder(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay = Replay(
        header=ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0),
        inputs=[[[0.0, 0.0, 0.0, 0.0, 0]]],
    )
    captured: dict[str, object] = {}

    class _StopOpen(Exception):
        pass

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
    mocker.patch.object(replay_playback_mode.ReplayPlaybackMode, "_open_world_runtime", return_value=None)
    mocker.patch.object(replay_playback_mode, "PlaybackDriver", _FakeDriver)

    with pytest.raises(_StopOpen):
        view.open()

    assert captured["defer_menu_open"] is False
