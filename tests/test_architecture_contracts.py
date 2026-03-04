from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import msgspec

import crimson.audio_router as audio_router_module
import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.modes.base_gameplay_mode import _LanRuntimeInputProvider
from crimson.modes.survival_mode import SurvivalMode
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay_file
from crimson.sim.clock import FixedStepClock
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    InputCommand,
    InputStatus,
    LocalInputProvider,
    NetworkInputProvider,
)
from crimson.sim.presentation_step import PresentationStepCommands
from crimson.sim.sessions import DeterministicSession
from crimson.sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from crimson.sim.timing import FrameTiming
from crimson.world import AudioBridge, SimWorldState
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


class _TickRunnerStackSpy:
    def __init__(self, sink: list[tuple[str, ...]]) -> None:
        self._sink = sink
        self.calls = 0
        self._last_frame_ctx: FrameContext | None = None

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        self._last_frame_ctx = frame_ctx

    def advance_ticks(self, *, start_tick: int, ticks_requested: int, tick_dt: float) -> TickBatchResult:
        _ = tick_dt
        self.calls += 1
        frames = inspect.stack()[1:8]
        self._sink.append(tuple(frame.function for frame in frames))
        return TickBatchResult(
            ticks_completed=0,
            batch_status=InputStatus.READY,
            next_tick_index=int(start_tick) + max(0, int(ticks_requested)),
            completed_results=[],
        )


class _PlanIsolationTick(msgspec.Struct):
    command_hash: str
    dt_sim: float
    presentation: PresentationStepCommands
    presentation_plan_ms: float


def _timing(dt: float) -> FrameTiming:
    return FrameTiming(dt=dt, time_scale_active_entry=False, time_scale_factor=1.0, zero_gate_active=False, dt_sim=dt)


class _PlanIsolationSession:
    def __init__(self, sim_world: SimWorldState) -> None:
        self._sim_world = sim_world
        self._tick = 0

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _timing(dt)

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> _PlanIsolationTick:
        _ = timing, inputs, trace_rng
        player = self._sim_world.players[0]
        player.health = max(0.0, float(player.health) - 10.0)
        player.experience = int(player.experience) + 250
        tick_index = int(self._tick)
        self._tick += 1
        return _PlanIsolationTick(
            command_hash=f"plan-{tick_index}",
            dt_sim=1.0 / 60.0,
            presentation=PresentationStepCommands(
                sfx_keys=["sfx_explosion", "sfx_ui_levelup"],
            ),
            presentation_plan_ms=0.0,
        )


class _CommandFlowTick(msgspec.Struct):
    command_hash: str
    dt_sim: float
    presentation: PresentationStepCommands
    presentation_plan_ms: float


class _CommandFlowSession:
    def __init__(self, *, name: str) -> None:
        self.name = str(name)
        self._tick = 0
        self.perk_pick_index: int | None = None
        self.commands_by_tick: dict[int, list[InputCommand]] = {}

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _timing(dt)

    def apply_commands(self, *, tick_index: int, commands: list[InputCommand]) -> None:
        self.commands_by_tick[int(tick_index)] = list(commands)
        for command in commands:
            if str(command.name) != "perk_pick":
                continue
            value = command.payload.get("index")
            if isinstance(value, int):
                self.perk_pick_index = int(value)

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> _CommandFlowTick:
        _ = timing, inputs, trace_rng
        tick_index = int(self._tick)
        self._tick += 1
        perk_index = -1 if self.perk_pick_index is None else int(self.perk_pick_index)
        return _CommandFlowTick(
            command_hash=f"{self.name}:{tick_index}:{perk_index}",
            dt_sim=1.0 / 60.0,
            presentation=PresentationStepCommands(),
            presentation_plan_ms=0.0,
        )


class _MockLockstepRuntime:
    def __init__(self) -> None:
        self._commands_by_peer_and_tick: dict[str, dict[int, list[InputCommand]]] = {
            "host": {},
            "client": {},
        }

    def broadcast_command(self, *, tick_index: int, command: InputCommand) -> None:
        self._commands_by_peer_and_tick["client"].setdefault(int(tick_index), []).append(command)

    def pull_commands(self, *, peer: str, tick_index: int) -> list[InputCommand]:
        return list(self._commands_by_peer_and_tick[str(peer)].pop(int(tick_index), []))


def _advance_with_clock(
    *,
    runner: TickRunner,
    clock: FixedStepClock,
    start_tick: int,
    frame_index: int,
    dt_seconds: float,
    max_ticks: int | None = None,
    is_networked: bool = False,
    is_replay: bool = False,
) -> tuple[TickBatchResult, int, int]:
    ticks_requested = int(clock.advance(float(dt_seconds)))
    if max_ticks is not None:
        ticks_requested = min(int(ticks_requested), max(0, int(max_ticks)))
    frame_index = int(frame_index) + 1
    runner.begin_frame(
        FrameContext(
            dt_seconds=float(dt_seconds),
            tick_dt_seconds=float(clock.dt_tick),
            frame_index=int(frame_index),
            candidate_ticks=max(0, int(ticks_requested)),
            is_networked=bool(is_networked),
            is_replay=bool(is_replay),
        ),
    )
    batch = runner.advance_ticks(
        start_tick=int(start_tick),
        ticks_requested=max(0, int(ticks_requested)),
        tick_dt=float(clock.dt_tick),
    )
    if batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
        unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
        if unconsumed_ticks > 0:
            clock.accum += float(unconsumed_ticks) * float(clock.dt_tick)
    return batch, int(batch.next_tick_index), int(frame_index)


def test_contract_1_pure_headless_execution_no_render_or_audio_dependencies(mocker) -> None:
    sim_world = SimWorldState(world_size=1024.0)
    session = DeterministicSession(
        world=sim_world.world_state,
        world_size=float(sim_world.world_size),
        damage_scale_by_type=sim_world.damage_scale_by_type,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
        detail_preset=5,
        gore_disabled=0,
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
    )
    provider = LocalInputProvider(
        player_count=len(sim_world.players),
        build_inputs=lambda _frame_ctx: [PlayerInput(aim=Vec2(512.0, 512.0))],
    )
    runner = TickRunner(
        session=session,
        input_provider=provider,
        config=TickRunnerConfig(),
    )
    play_sfx = mocker.patch.object(
        audio_router_module,
        "play_sfx",
        wraps=audio_router_module.play_sfx,
    )

    completed: list[object] = []
    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0
    for _ in range(60):
        batch, next_tick_index, frame_index = _advance_with_clock(
            runner=runner,
            clock=clock,
            start_tick=next_tick_index,
            frame_index=frame_index,
            dt_seconds=1.0 / 60.0,
            max_ticks=1,
        )
        assert batch.ticks_completed == 1
        completed.extend(batch.completed_results)

    assert int(next_tick_index) == 60
    assert len(completed) == 60
    assert play_sfx.call_count == 0
    for result in completed:
        payload = cast(Any, result).payload
        assert payload is not None
        assert isinstance(payload.step.presentation, PresentationStepCommands)
        assert str(payload.command_hash)


def test_contract_2_control_flow_parity_local_and_lan_use_identical_runner_stack(mocker) -> None:
    local_mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    lan_mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))

    local_stacks: list[tuple[str, ...]] = []
    lan_stacks: list[tuple[str, ...]] = []
    local_runner = _TickRunnerStackSpy(local_stacks)
    lan_runner = _TickRunnerStackSpy(lan_stacks)
    local_provider = LocalInputProvider(
        player_count=1,
        build_inputs=lambda _frame_ctx: [PlayerInput()],
    )
    lan_provider = _LanRuntimeInputProvider(
        player_count=1,
        tick_rate=60,
    )

    local_mode.state.perk_selection.pending_count = 0
    lan_mode.state.perk_selection.pending_count = 0
    lan_mode.bind_lan_runtime(cast(Any, SimpleNamespace(local_slot_index=0)))
    lan_mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=1,
        connected_players=1,
        waiting_for_players=False,
    )

    mode_frame = SimpleNamespace(dt=0.016, dt_ui_ms=16.0)

    mocker.patch.object(local_mode, "_begin_mode_update", return_value=mode_frame)
    mocker.patch.object(local_mode, "_sync_audio_and_ground", return_value=None)
    mocker.patch.object(local_mode, "_death_transition_ready", return_value=False)
    mocker.patch.object(local_mode, "_lan_wait_gate_active", return_value=False)
    mocker.patch.object(
        local_mode,
        "_ensure_tick_runner",
        return_value=(local_runner, local_provider),
    )

    mocker.patch.object(lan_mode, "_begin_mode_update", return_value=mode_frame)
    mocker.patch.object(lan_mode, "_prepare_lan_match_runtime", return_value="host")
    mocker.patch.object(lan_mode, "_trace_lan_terrain_generation", return_value=None)
    mocker.patch.object(lan_mode, "_lan_terrain_generation_pending", return_value=False)
    mocker.patch.object(lan_mode, "_prepare_lan_frame", return_value=True)
    mocker.patch.object(lan_mode, "_advance_lan_capture_ticks", return_value=0)
    mocker.patch.object(lan_mode, "_queue_lan_local_inputs", return_value=None)
    mocker.patch.object(
        lan_mode,
        "_ensure_tick_runner",
        return_value=(lan_runner, lan_provider),
    )

    local_mode.update(0.016)
    lan_mode.update(0.016)

    assert local_runner.calls == 1
    assert lan_runner.calls == 1
    assert local_stacks and lan_stacks
    assert local_stacks[0][0] == lan_stacks[0][0]


def test_contract_3_lockstep_command_propagation_over_network_provider() -> None:
    runtime = _MockLockstepRuntime()
    tick_input = [PlayerInput()]
    host_provider = NetworkInputProvider(
        player_count=1,
        resolve_tick_input=lambda _tick: list(tick_input),
        resolve_tick_commands=lambda tick: runtime.pull_commands(peer="host", tick_index=int(tick)),
        emit_tick_command=lambda tick, command: runtime.broadcast_command(
            tick_index=int(tick),
            command=command,
        ),
    )
    client_provider = NetworkInputProvider(
        player_count=1,
        resolve_tick_input=lambda _tick: list(tick_input),
        resolve_tick_commands=lambda tick: runtime.pull_commands(peer="client", tick_index=int(tick)),
    )
    host_session = _CommandFlowSession(name="host")
    client_session = _CommandFlowSession(name="client")

    host_runner = TickRunner(
        session=host_session,
        input_provider=host_provider,
        config=TickRunnerConfig(),
    )
    client_runner = TickRunner(
        session=client_session,
        input_provider=client_provider,
        config=TickRunnerConfig(),
    )

    command = InputCommand("perk_pick", {"index": 1})
    host_provider.push_command(command)

    host_clock = FixedStepClock(tick_rate=60)
    host_frame_index = 0
    host_next_tick_index = 0
    _host_batch, host_next_tick_index, host_frame_index = _advance_with_clock(
        runner=host_runner,
        clock=host_clock,
        start_tick=host_next_tick_index,
        frame_index=host_frame_index,
        dt_seconds=1.0 / 60.0,
        max_ticks=1,
        is_networked=True,
    )
    host_commands = host_provider.pull_tick_commands(0)
    host_session.apply_commands(tick_index=0, commands=list(host_commands))

    client_clock = FixedStepClock(tick_rate=60)
    client_frame_index = 0
    client_next_tick_index = 0
    _client_batch, client_next_tick_index, client_frame_index = _advance_with_clock(
        runner=client_runner,
        clock=client_clock,
        start_tick=client_next_tick_index,
        frame_index=client_frame_index,
        dt_seconds=1.0 / 60.0,
        max_ticks=1,
        is_networked=True,
    )
    client_commands = client_provider.pull_tick_commands(0)
    client_session.apply_commands(tick_index=0, commands=list(client_commands))

    assert host_session.commands_by_tick.get(0, []) == [command]
    assert client_session.commands_by_tick.get(0, []) == [command]
    assert host_session.perk_pick_index == 1
    assert client_session.perk_pick_index == 1


def test_contract_4_live_to_replay_uses_survival_session_and_matches_command_hashes(
    mocker,
    tmp_path: Path,
) -> None:
    tick_count = 10
    input_row = [PlayerInput(aim=Vec2(512.0, 512.0))]
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
        world_size=1024.0,
        detail_preset=5,
        gore_disabled=0,
    )
    recorder = ReplayRecorder(header)

    sim_world = SimWorldState(world_size=1024.0)
    sim_world.reset(seed=int(header.seed), player_count=int(header.player_count))
    live_session = DeterministicSession(
        world=sim_world.world_state,
        world_size=float(sim_world.world_size),
        damage_scale_by_type=sim_world.damage_scale_by_type,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
        detail_preset=int(header.detail_preset),
        gore_disabled=int(header.gore_disabled),
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
    )
    live_provider = LocalInputProvider(
        player_count=1,
        build_inputs=lambda _frame_ctx: list(input_row),
    )
    live_runner = TickRunner(
        session=live_session,
        input_provider=live_provider,
        config=TickRunnerConfig(),
    )
    live_clock = FixedStepClock(tick_rate=int(header.tick_rate))
    live_frame_index = 0
    live_next_tick_index = 0

    live_hashes: list[str] = []
    for _ in range(int(tick_count)):
        recorder.record_tick(list(input_row))
        batch, live_next_tick_index, live_frame_index = _advance_with_clock(
            runner=live_runner,
            clock=live_clock,
            start_tick=live_next_tick_index,
            frame_index=live_frame_index,
            dt_seconds=1.0 / 60.0,
            max_ticks=1,
        )
        assert batch.ticks_completed == 1
        live_hashes.append(str(batch.completed_results[0].command_hash))

    replay = recorder.finish()
    replay_path = tmp_path / "contract_live_to_replay.crd"
    dump_replay_file(replay_path, replay)

    cfg = ensure_crimson_cfg(tmp_path)
    console = create_console(tmp_path, assets_dir=_assets_dir())
    mode = replay_playback_mode.ReplayPlaybackMode(
        ViewContext(assets_dir=_assets_dir()),
        replay_path=replay_path,
        config=cfg,
        console=console,
        max_ticks=tick_count,
    )

    mocker.patch.object(replay_playback_mode, "load_small_font", return_value=None)
    mocker.patch.object(replay_playback_mode, "load_hud_assets", return_value=None)
    mocker.patch.object(replay_playback_mode, "init_audio_state", return_value=None)
    mocker.patch.object(mode, "_open_world_runtime", return_value=None)

    mode.open()
    assert isinstance(mode._survival, DeterministicSession)

    replay_hashes: list[str] = []

    def _capture_runner_tick(_tick_index: int, tick: object) -> bool:
        replay_hashes.append(str(cast(Any, tick).command_hash))
        return False

    mocker.patch.object(mode, "_on_runner_tick_complete", side_effect=_capture_runner_tick)
    for _ in range(int(tick_count)):
        mode._advance_runner(
            dt_seconds=float(mode._dt),
            max_ticks=1,
        )

    assert replay_hashes == live_hashes
    mode.close()


def test_contract_5_plan_vs_apply_isolation_for_audio_and_render_side_effects(mocker) -> None:
    sim_world = SimWorldState(world_size=1024.0)
    before_health = float(sim_world.players[0].health)
    before_xp = int(sim_world.players[0].experience)

    provider = LocalInputProvider(
        player_count=1,
        build_inputs=lambda _frame_ctx: [PlayerInput()],
    )
    runner = TickRunner(
        session=_PlanIsolationSession(sim_world),
        input_provider=provider,
        config=TickRunnerConfig(),
    )

    audio_bridge = AudioBridge(
        demo_mode_active=False,
        reflex_boost_timer_source=lambda: 0.0,
        audio=cast(Any, object()),
        audio_rng=None,
    )
    play_sfx = mocker.patch.object(audio_router_module, "play_sfx")
    draw_text = mocker.patch.object(rl, "draw_text")

    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0
    batch, next_tick_index, frame_index = _advance_with_clock(
        runner=runner,
        clock=clock,
        start_tick=next_tick_index,
        frame_index=frame_index,
        dt_seconds=1.0 / 60.0,
        max_ticks=1,
    )
    assert batch.ticks_completed == 1
    assert float(sim_world.players[0].health) < before_health
    assert int(sim_world.players[0].experience) > before_xp
    assert play_sfx.call_count == 0
    assert draw_text.call_count == 0

    payload = cast(Any, batch.completed_results[0].payload)
    plan = cast(PresentationStepCommands, payload.presentation)
    audio_bridge.apply_plan(plan=plan, apply_audio=True)

    assert [str(call.args[1]) for call in play_sfx.call_args_list] == [
        "sfx_explosion",
        "sfx_ui_levelup",
    ]
