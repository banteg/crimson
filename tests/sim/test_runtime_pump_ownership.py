"""Frame-driver orchestration tests.

These tests isolate orchestration logic (pump counting, stall detection,
sync emission suppression, telemetry propagation) from the sim layer
using mocks. The mocking is intentional: each test asserts an observable
behavioral contract of the frame-driver, not internal wiring.
"""

from __future__ import annotations

from pathlib import Path

import crimson.game.loop_view as loop_view_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, NetworkSessionConfig, PendingNetworkSession
from crimson.game_modes import GameMode
from crimson.modes.base_gameplay_mode import _LanRuntimeInputProvider, _LanTickSyncRuntime
from crimson.modes.survival_mode import SurvivalMode
from crimson.net.lockstep_protocol import TickFrame
from crimson.net.lockstep_runtime import HostLockstepRuntimeConfig, LockstepRuntime
from crimson.sim.hooks import LanFrameSample, LanTickSync, TickResult
from crimson.sim.input_providers import InputStatus, PerkPickCommand, ResolvedTick
from crimson.sim.tick_runner import TickBatchResult
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.builders import FakeRunner, make_tick_payload
from tests.support.builders.session import make_session
from tests.support.gameplay_screen import GameplayScreenStub


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


class _BroadcastTickFrameRuntime:
    def __init__(self) -> None:
        self.frames: list[TickFrame] = []

    def broadcast_tick_frame(self, frame: TickFrame) -> None:
        self.frames.append(frame)


def _pending_session() -> PendingNetworkSession:
    return PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode="survival",
            endpoint=LockstepEndpoint(),
            netcode_mode="lockstep",
            player_count=2,
        ),
    )


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def _host_lan_runtime() -> LockstepRuntime:
    return LockstepRuntime(
        HostLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=1,
            bind_host="127.0.0.1",
            host_ip="127.0.0.1",
            port=0,
        ),
    )


def _mode_rng() -> Crand:
    return Crand(0xBEEF)


def _survival_mode(*, config) -> SurvivalMode:
    return SurvivalMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=_mode_rng())


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


def test_lan_tick_consumption_drives_runner_until_stall(mocker, make_mode_config) -> None:
    mode = _survival_mode(config=make_mode_config(game_mode=GameMode.SURVIVAL))
    tick_payload = make_tick_payload()
    runner = FakeRunner(results=
        [
            TickBatchResult(
                ticks_completed=1,
                batch_status=InputStatus.READY,
                next_tick_index=1,
                completed_results=[
                    TickResult(
                        source_tick=ResolvedTick(
                            tick_index=0,
                            dt_seconds=1.0 / 60.0,
                            inputs=(),
                            commands=(),
                        ),
                        payload=tick_payload,
                        lan_sync=LanTickSync(
                            frame_tick_index=0,
                            frame_inputs=([],),
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
    mocker.patch.object(mode, "_build_lan_tick_sync_runtime", return_value=None)
    mocker.patch.object(mode, "_lan_on_tick_applied", return_value="continue")
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=_host_lan_runtime(),
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert runner.calls == 1
    assert mode._input_stall_count == 0


def test_lan_tick_consumption_treats_before_pop_block_as_non_stall(mocker, make_mode_config) -> None:
    mode = _survival_mode(config=make_mode_config(game_mode=GameMode.SURVIVAL))
    provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )
    runner = FakeRunner(results=
        [TickBatchResult(ticks_completed=0, batch_status=InputStatus.STALLED, next_tick_index=0)],
        on_advance=lambda: setattr(provider, "_pop_blocked", True),
    )
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )
    mocker.patch.object(mode, "_build_lan_tick_sync_runtime", return_value=None)

    before_stall_count = int(mode._input_stall_count)
    stop = mode._consume_lan_tick_frames(
        runtime=_host_lan_runtime(),
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert runner.calls == 1
    assert int(mode._input_stall_count) == before_stall_count


def test_lan_tick_consumption_does_not_emit_sync_for_stop_before_finalize(mocker, make_mode_config) -> None:
    mode = _survival_mode(config=make_mode_config(game_mode=GameMode.SURVIVAL))
    ticks = [
        TickResult(
            source_tick=ResolvedTick(
                tick_index=0,
                dt_seconds=1.0 / 60.0,
                inputs=(),
                commands=(),
            ),
            payload=make_tick_payload(elapsed_ms=16.67),
        ),
        TickResult(
            source_tick=ResolvedTick(
                tick_index=1,
                dt_seconds=1.0 / 60.0,
                inputs=(),
                commands=(),
            ),
            payload=make_tick_payload(elapsed_ms=33.33),
        ),
    ]
    provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )
    sync_samples = {
        0: LanFrameSample(
            frame_tick_index=10,
            frame_inputs=([],),
            commands=(),
        ),
        1: LanFrameSample(
            frame_tick_index=11,
            frame_inputs=([],),
            commands=(),
        ),
    }
    runner = FakeRunner(
        results=[
            TickBatchResult(
                ticks_completed=2,
                batch_status=InputStatus.READY,
                next_tick_index=2,
                completed_results=ticks,
            ),
        ],
        on_advance=lambda: provider._samples_by_runner_tick.update(sync_samples),
    )
    runtime = _BroadcastTickFrameRuntime()
    tick_sync = _LanTickSyncRuntime(
        role="host",
        provider=provider,
        lockstep_runtime=runtime,
    )

    mocker.patch.object(mode, "_build_lan_tick_sync_runtime", return_value=tick_sync)
    mocker.patch.object(mode, "_lan_on_tick_applied", return_value="stop_before_finalize")
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=_host_lan_runtime(),
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert runner.calls == 1
    assert runtime.frames == []
    # Tick 1 was not finalized and its sample should remain untouched.
    assert 1 in provider._samples_by_runner_tick


def test_lan_tick_consumption_broadcasts_tick_frame_commands(mocker, make_mode_config) -> None:
    mode = _survival_mode(config=make_mode_config(game_mode=GameMode.SURVIVAL))
    command = PerkPickCommand(player_index=0, choice_index=2)
    tick = TickResult(
        source_tick=ResolvedTick(
            tick_index=0,
            dt_seconds=1.0 / 60.0,
            inputs=(),
            commands=(command,),
        ),
        payload=make_tick_payload(elapsed_ms=16.67),
    )
    provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )
    sync_samples = {
        0: LanFrameSample(
            frame_tick_index=10,
            frame_inputs=([],),
            commands=(command,),
        ),
    }
    runner = FakeRunner(
        results=[
            TickBatchResult(
                ticks_completed=1,
                batch_status=InputStatus.READY,
                next_tick_index=1,
                completed_results=[tick],
            ),
        ],
        on_advance=lambda: provider._samples_by_runner_tick.update(sync_samples),
    )
    runtime = _BroadcastTickFrameRuntime()
    tick_sync = _LanTickSyncRuntime(
        role="host",
        provider=provider,
        lockstep_runtime=runtime,
    )
    mocker.patch.object(mode, "_build_lan_tick_sync_runtime", return_value=tick_sync)
    mocker.patch.object(
        mode,
        "_ensure_tick_runner",
        return_value=(runner, provider),
    )

    stop = mode._consume_lan_tick_frames(
        runtime=_host_lan_runtime(),
        lockstep_runtime=None,
        session=make_session()[0],
        role="host",
        dt_tick=1.0 / 60.0,
    )

    assert stop is False
    assert [(int(frame.tick_index), tuple(frame.commands)) for frame in runtime.frames] == [(10, (command,))]


def test_gameplay_frame_telemetry_is_propagated_to_game_state(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)
    view = GameplayScreenStub(telemetry=(3, 2, 5, 1.25, 0.75, 0.5))
    loop._front_active = view
    loop._active = view

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
