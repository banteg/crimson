"""Frame-driver orchestration tests.

These tests isolate orchestration logic (pump counting, stall detection,
sync emission suppression, telemetry propagation) from the sim layer
using mocks. The mocking is intentional: each test asserts an observable
behavioral contract of the frame-driver, not internal wiring.
"""

from __future__ import annotations

from pathlib import Path

from builders import FakeRunner, make_tick_payload
from builders.session import make_session

import crimson.game.loop_view as loop_view_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, LockstepSessionConfig, PendingNetworkSession
from crimson.modes.base_gameplay_mode import LanFramePolicy, _LanRuntimeInputProvider
from crimson.modes.survival_mode import SurvivalMode
from crimson.sim.hooks import LanFrameSample, LanSyncCallbacks, LanTickSync, TickResult
from crimson.sim.input_providers import InputStatus
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


def test_lan_tick_consumption_drives_runner_until_stall(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    tick_payload = make_tick_payload()
    runner = FakeRunner(results=
        [
            TickBatchResult(
                ticks_completed=1,
                batch_status=InputStatus.READY,
                next_tick_index=1,
                completed_results=[
                    TickResult(
                        tick_index=0,
                        payload=tick_payload,
                        inputs=[],
                        commands=[],
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
    provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )
    policy = LanFramePolicy(on_tick_applied=lambda _tick, _fti, _dt: "continue")
    mocker.patch.object(mode, "_build_lan_sync_callbacks", return_value=None)
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=object(),  # type: ignore[arg-type]  # _ensure_tick_runner is patched
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
        policy=policy,
    )

    assert stop is False
    assert runner.calls == 1
    assert mode._input_stall_count == 0


def test_lan_tick_consumption_treats_before_pop_block_as_non_stall(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )
    runner = FakeRunner(results=
        [TickBatchResult(ticks_completed=0, batch_status=InputStatus.STALLED, next_tick_index=0)],
        on_advance=lambda: setattr(provider, "_pop_blocked", True),
    )
    policy = LanFramePolicy()
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )
    mocker.patch.object(mode, "_build_lan_sync_callbacks", return_value=None)

    before_stall_count = int(mode._input_stall_count)
    stop = mode._consume_lan_tick_frames(
        runtime=object(),  # type: ignore[arg-type]  # _ensure_tick_runner is patched
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
        policy=policy,
    )

    assert stop is False
    assert runner.calls == 1
    assert int(mode._input_stall_count) == before_stall_count


def test_lan_tick_consumption_does_not_emit_sync_for_stop_before_finalize(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    ticks = [
        TickResult(
            tick_index=0,
            payload=make_tick_payload(elapsed_ms=16.67),
            inputs=[],
            commands=[],
        ),
        TickResult(
            tick_index=1,
            payload=make_tick_payload(elapsed_ms=33.33),
            inputs=[],
            commands=[],
        ),
    ]
    runner = FakeRunner(results=
        [
            TickBatchResult(
                ticks_completed=2,
                batch_status=InputStatus.READY,
                next_tick_index=2,
                completed_results=ticks,
            ),
        ],
    )
    provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )
    sync_samples = {
        0: LanFrameSample(
            frame_tick_index=10,
            frame_inputs=([],),
            remote_command_hash="",
            remote_state_hash="",
        ),
        1: LanFrameSample(
            frame_tick_index=11,
            frame_inputs=([],),
            remote_command_hash="",
            remote_state_hash="",
        ),
    }
    broadcast_calls: list[int] = []
    callbacks = LanSyncCallbacks(
        role="host",
        take_frame_sample=lambda tick: sync_samples.pop(int(tick), None),
        state_hash_for_tick=lambda _frame_tick_index, _result: "state-hash",
        should_emit_state_hash=lambda _frame_tick_index: True,
        note_desync=lambda *_args: None,
        broadcast_tick_frame=lambda frame_tick_index, _frame_inputs, _command_hash, _state_hash: broadcast_calls.append(
            int(frame_tick_index),
        ),
    )

    policy = LanFramePolicy(on_tick_applied=lambda _tick, _fti, _dt: "stop_before_finalize")
    mocker.patch.object(mode, "_build_lan_sync_callbacks", return_value=callbacks)
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=object(),  # type: ignore[arg-type]  # _ensure_tick_runner is patched
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
        policy=policy,
    )

    assert stop is False
    assert runner.calls == 1
    assert broadcast_calls == []
    # Tick 1 was not finalized and its sample should remain untouched.
    assert 1 in sync_samples


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
