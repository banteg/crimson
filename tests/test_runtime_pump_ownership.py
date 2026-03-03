from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import crimson.game.loop_view as loop_view_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, LockstepSessionConfig, PendingNetworkSession
from crimson.modes.survival_mode import SurvivalMode
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
        return TickBatchResult(ticks_completed=0, stalled=True, remaining_debt_ticks=0, presentation_plans=[])


class _FakeLanProvider:
    def __init__(self) -> None:
        self.runtime = None
        self.before_pop = None
        self.pop_blocked = False

    def bind_runtime(self, runtime) -> None:
        self.runtime = runtime

    def set_before_pop(self, callback) -> None:
        self.before_pop = callback


class _FakePreSimHook:
    def __init__(self) -> None:
        self.dt_tick = 0.0
        self.before_step = None

    def bind(self, *, dt_tick: float, before_step) -> None:
        self.dt_tick = float(dt_tick)
        self.before_step = before_step


class _FakeFinalizeHook:
    def __init__(self, *, ticks_applied: int = 0, stop_requested: bool = False, stop_after_finalize: bool = False) -> None:
        self.ticks_applied = int(ticks_applied)
        self.stop_requested = bool(stop_requested)
        self.stop_after_finalize = bool(stop_after_finalize)

    def bind(self, **_kwargs) -> None:
        return


def test_lan_tick_consumption_drives_runner_until_stall(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    runner = _FakeLanRunner(
        [
            TickBatchResult(ticks_completed=1, stalled=False, remaining_debt_ticks=0, presentation_plans=[]),
            TickBatchResult(ticks_completed=0, stalled=True, remaining_debt_ticks=0, presentation_plans=[]),
        ],
    )
    provider = _FakeLanProvider()
    pre_sim_hook = _FakePreSimHook()
    profiler = SimpleNamespace(sim_ms=1.5, presentation_plan_ms=0.75, presentation_apply_ms=0.25)
    finalize_hook = _FakeFinalizeHook(ticks_applied=1)
    mocker.patch.object(
        mode,
        "_ensure_lan_tick_runner",
        return_value=(runner, provider, pre_sim_hook, profiler, finalize_hook),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=cast(Any, SimpleNamespace()),
        lockstep_runtime=None,
        session=cast(Any, SimpleNamespace(game_tune_started=False)),
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert runner.calls == 2
    assert mode._input_stall_count == 0


def test_lan_tick_consumption_treats_before_pop_block_as_non_stall(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    provider = _FakeLanProvider()
    runner = _FakeLanRunner(
        [TickBatchResult(ticks_completed=0, stalled=True, remaining_debt_ticks=0, presentation_plans=[])],
        on_advance=lambda: setattr(provider, "pop_blocked", True),
    )
    pre_sim_hook = _FakePreSimHook()
    profiler = SimpleNamespace(sim_ms=0.0, presentation_plan_ms=0.0, presentation_apply_ms=0.0)
    finalize_hook = _FakeFinalizeHook(ticks_applied=0)
    mocker.patch.object(
        mode,
        "_ensure_lan_tick_runner",
        return_value=(runner, provider, pre_sim_hook, profiler, finalize_hook),
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
