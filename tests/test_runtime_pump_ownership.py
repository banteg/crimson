from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import crimson.game.loop_view as loop_view_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, LockstepSessionConfig, PendingNetworkSession
from crimson.modes.survival_mode import SurvivalMode
from crimson.sim.hooks import CheckpointHook, LanTickSync, NetworkSyncHook, ReplayRecorderHook, TickResult
from crimson.sim.tick_runner import TickBatchResult
from grim.view import ViewContext


class _DummyRuntime:
    def __init__(self) -> None:
        self.open_calls = 0
        self.update_calls = 0
        self.desync_count = 0
        self.error = ""

    def open(self) -> None:
        self.open_calls += 1

    def update(self) -> None:
        self.update_calls += 1

    def lobby_state(self):
        return None


def _pending_session() -> PendingNetworkSession:
    return PendingNetworkSession(
        role="host",
        config=LockstepSessionConfig(
            mode="survival",
            endpoint=LockstepEndpoint(),
            player_count=2,
        ),
    )


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_interactive_frame_driver_pumps_runtime_once(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _pending_session()
    state.network_in_lobby = True
    runtime = _DummyRuntime()
    state.network_runtime = runtime
    loop = GameLoopView(state)

    loop._tick_network_runtime()

    assert runtime.open_calls == 1
    assert runtime.update_calls == 1
    assert state.runtime_updates_per_frame == 1


def test_interactive_headless_no_runtime_pumps_zero(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _pending_session()
    state.network_in_lobby = True
    state.network_runtime = None
    loop = GameLoopView(state)

    loop._tick_network_runtime()

    assert state.runtime_updates_per_frame == 0


class _FakeLanRunner:
    def __init__(self, results: list[TickBatchResult], *, on_advance=None) -> None:
        self._results = list(results)
        self._on_advance = on_advance
        self.calls = 0

    def advance_frame(self, *_args, **_kwargs) -> TickBatchResult:
        self.calls += 1
        if callable(self._on_advance):
            self._on_advance()
        if self._results:
            return self._results.pop(0)
        return TickBatchResult(ticks_completed=0, stalled=True, remaining_debt_ticks=0)


class _FakeLanProvider:
    def __init__(self) -> None:
        self.runtime = None
        self.before_pop = None
        self.pop_blocked = False
        self.samples_by_tick: dict[int, object] = {}

    def bind_runtime(self, runtime) -> None:
        self.runtime = runtime

    def set_before_pop(self, callback) -> None:
        self.before_pop = callback

    def take_frame_sample(self, runner_tick_index: int):
        return self.samples_by_tick.pop(int(runner_tick_index), None)


def test_lan_tick_consumption_drives_runner_until_stall(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    tick_payload = SimpleNamespace(
        step=SimpleNamespace(
            events=SimpleNamespace(),
            command_hash="cmd-hash",
            dt_sim=1.0 / 60.0,
            presentation=None,
            presentation_plan_ms=0.0,
        ),
        elapsed_ms=16.67,
        creature_count_world_step=0,
    )
    runner = _FakeLanRunner(
        [
            TickBatchResult(
                ticks_completed=1,
                stalled=False,
                remaining_debt_ticks=0,
                completed_results=[
                    TickResult(
                        tick_index=0,
                        command_hash="cmd-hash",
                        dt_sim=1.0 / 60.0,
                        presentation_plan_ms=0.0,
                        payload=tick_payload,
                        lan_sync=LanTickSync(
                            frame_tick_index=0,
                            frame_inputs=([],),
                            remote_command_hash="",
                            remote_state_hash="",
                        ),
                    ),
                ],
            ),
        ],
    )
    provider = _FakeLanProvider()
    provider.samples_by_tick[0] = SimpleNamespace(
        frame_tick_index=0,
        frame_inputs=([],),
        remote_command_hash="",
        remote_state_hash="",
    )
    replay_hook = ReplayRecorderHook(None)
    checkpoint_hook = CheckpointHook(replay_recorder_hook=replay_hook)
    network_sync_hook = NetworkSyncHook()
    profiler = SimpleNamespace(sim_ms=1.5, presentation_plan_ms=0.75, presentation_apply_ms=0.25)
    fake_policy = SimpleNamespace(
        prepare_frame=lambda _phase: True,
        before_tick_step=lambda _phase: None,
        allow_frame_pop=lambda _phase: True,
        after_join_consume=lambda _phase: False,
        on_tick_applied=lambda _phase: "continue",
    )
    mocker.patch.object(mode, "_resolve_lan_mode_policy", return_value=fake_policy)
    mocker.patch.object(mode, "_apply_sim_step_result", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(
        mode,
        "_ensure_lan_tick_runner",
        return_value=(runner, provider, replay_hook, checkpoint_hook, network_sync_hook, profiler),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=cast(Any, SimpleNamespace()),
        lockstep_runtime=None,
        session=cast(Any, SimpleNamespace(game_tune_started=False)),
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert runner.calls == 1
    assert mode._input_stall_count == 0


def test_lan_tick_consumption_treats_before_pop_block_as_non_stall(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    provider = _FakeLanProvider()
    runner = _FakeLanRunner(
        [TickBatchResult(ticks_completed=0, stalled=True, remaining_debt_ticks=0)],
        on_advance=lambda: setattr(provider, "pop_blocked", True),
    )
    replay_hook = ReplayRecorderHook(None)
    checkpoint_hook = CheckpointHook(replay_recorder_hook=replay_hook)
    network_sync_hook = NetworkSyncHook()
    profiler = SimpleNamespace(sim_ms=0.0, presentation_plan_ms=0.0, presentation_apply_ms=0.0)
    fake_policy = SimpleNamespace(
        prepare_frame=lambda _phase: True,
        before_tick_step=lambda _phase: None,
        allow_frame_pop=lambda _phase: True,
        after_join_consume=lambda _phase: False,
        on_tick_applied=lambda _phase: "continue",
    )
    mocker.patch.object(mode, "_resolve_lan_mode_policy", return_value=fake_policy)
    mocker.patch.object(
        mode,
        "_ensure_lan_tick_runner",
        return_value=(runner, provider, replay_hook, checkpoint_hook, network_sync_hook, profiler),
    )

    before_stall_count = int(mode._input_stall_count)
    stop = mode._consume_lan_tick_frames(
        runtime=cast(Any, SimpleNamespace()),
        lockstep_runtime=None,
        session=cast(Any, SimpleNamespace(game_tune_started=False)),
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert runner.calls == 1
    assert int(mode._input_stall_count) == before_stall_count


def test_gameplay_frame_telemetry_is_propagated_to_game_state(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)

    class _FakeGameplayView:
        def open(self) -> None:
            return

        def close(self) -> None:
            return

        def update(self, dt: float) -> None:
            _ = dt

        def draw(self) -> None:
            return

        def take_action(self) -> str | None:
            return None

        def set_runtime_updates_per_frame(self, value: int) -> None:
            _ = value

        def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
            return (3, 2, 5, 1.25, 0.75, 0.5)

    view = _FakeGameplayView()
    loop._front_active = view
    loop._active = view
    loop._gameplay_views = frozenset({view})

    mocker.patch.object(loop_view_module, "input_begin_frame", side_effect=lambda: None)
    mocker.patch.object(type(state.console), "handle_hotkey", return_value=None)
    mocker.patch.object(type(state.console), "update", return_value=None)
    mocker.patch.object(loop, "_sync_console_elapsed_ms", side_effect=lambda: None)
    mocker.patch.object(loop, "_handle_console_requests", side_effect=lambda: None)
    mocker.patch.object(loop, "_sync_rtx_mode", side_effect=lambda: None)
    mocker.patch.object(loop, "_tick_statistics_playtime", side_effect=lambda _dt: None)
    mocker.patch.object(loop_view_module, "debug_enabled", return_value=False)
    mocker.patch.object(loop_view_module, "_update_screen_fade", side_effect=lambda _state, _dt: None)

    loop.update(1.0 / 60.0)

    assert state.runtime_updates_per_frame == 3
    assert state.input_stall_count == 2
    assert state.ticks_advanced_per_frame == 5
    assert state.sim_ms == 1.25
    assert state.presentation_plan_ms == 0.75
    assert state.presentation_apply_ms == 0.5
