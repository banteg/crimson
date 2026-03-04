from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, cast

from grim.config import CrimsonConfig

from ..game_modes import GameMode
from ..world import AudioBridge, RenderResources, SimWorldState, TerrainRuntime
from .clock import FixedStepClock
from .input import PlayerInput
from .input_providers import FrameContext, InputStatus, LocalInputProvider
from .sessions import DeterministicSession, DeterministicSessionTick
from .step_pipeline import StepPipelineOptions, run_deterministic_step, time_scale_reflex_boost_factor
from .tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from .timing import FrameTiming, zero_gate_active_from_state
from .world_state import ProjectileHit

WorldTickInputBuilder = Callable[[FrameContext], Sequence[PlayerInput]]


class WorldHost(Protocol):
    world_size: float
    config: CrimsonConfig | None
    demo_mode_active: bool
    sim_world: SimWorldState
    render_resources: RenderResources
    audio_bridge: AudioBridge
    terrain_runtime: TerrainRuntime

    def sync_audio_bridge_state(self) -> None: ...

    def update_camera(self, dt: float) -> None: ...


def step_world_once(
    world: WorldHost,
    dt: float,
    *,
    inputs: list[PlayerInput] | None = None,
    auto_pick_perks: bool = False,
    game_mode: GameMode = GameMode.SURVIVAL,
    perk_progression_enabled: bool = False,
    defer_camera_shake_update: bool = False,
    rng_marks_out: dict[str, int] | None = None,
) -> list[ProjectileHit]:
    world.sync_audio_bridge_state()

    detail_preset = 5
    gore_disabled = 0
    if world.config is not None:
        detail_preset = world.config.detail_preset
        gore_disabled = world.config.gore_disabled

    world.terrain_runtime.process_pending()

    timing = FrameTiming.compute(
        float(dt),
        time_scale_active_entry=bool(world.sim_world.state.time_scale_active),
        time_scale_factor=time_scale_reflex_boost_factor(
            reflex_boost_timer=float(world.sim_world.state.bonuses.reflex_boost),
            time_scale_active=bool(world.sim_world.state.time_scale_active),
        ),
        zero_gate_active=zero_gate_active_from_state(
            demo_mode_active=bool(world.sim_world.state.demo_mode_active),
        ),
    )

    step = run_deterministic_step(
        world=world.sim_world.world_state,
        timing=timing,
        options=StepPipelineOptions(
            world_size=float(world.world_size),
            damage_scale_by_type=world.sim_world.damage_scale_by_type,
            detail_preset=int(detail_preset),
            gore_disabled=int(gore_disabled),
            auto_pick_perks=bool(auto_pick_perks),
            game_mode=game_mode,
            demo_mode_active=bool(world.demo_mode_active),
            perk_progression_enabled=bool(perk_progression_enabled),
            game_tune_started=bool(world.sim_world.game_tune_started),
        ),
        inputs=inputs,
        fx_queue=world.render_resources.fx_queue,
        fx_queue_rotated=world.render_resources.fx_queue_rotated,
        defer_camera_shake_update=bool(defer_camera_shake_update),
        rng_marks_out=rng_marks_out,
    )
    world.sim_world.apply_step_metadata(
        events=step.events,
        presentation=step.presentation,
        command_hash=str(step.command_hash),
        dt_sim=float(step.dt_sim),
        game_tune_started=bool(world.sim_world.game_tune_started) or step.presentation.trigger_game_tune,
    )
    world.sync_audio_bridge_state()
    world.audio_bridge.apply_plan(
        plan=step.presentation,
        apply_audio=True,
    )
    world.update_camera(float(step.dt_sim))
    return step.events.hits


class WorldTickRunnerHarness:
    def __init__(
        self,
        *,
        world: WorldHost,
        game_mode: GameMode,
        build_inputs: WorldTickInputBuilder,
        tick_rate: int = 60,
    ) -> None:
        self._world = world
        self._game_mode = game_mode
        self._build_inputs = build_inputs
        self._tick_rate = max(1, int(tick_rate))
        self._session: DeterministicSession | None = None
        self._runner: TickRunner | None = None
        self._world_state: object | None = None
        self._player_count = 0
        self._clock = FixedStepClock(tick_rate=int(self._tick_rate))
        self._frame_index = 0
        self._next_tick_index = 0

    def reset(self) -> None:
        self._session = None
        self._runner = None
        self._world_state = None
        self._player_count = 0
        self._clock = FixedStepClock(tick_rate=int(self._tick_rate))
        self._frame_index = 0
        self._next_tick_index = 0

    def _ensure_runner(self) -> tuple[TickRunner, DeterministicSession]:
        world_state = self._world.sim_world.world_state
        player_count = len(self._world.sim_world.players)
        session = self._session
        runner = self._runner
        if (
            session is not None
            and runner is not None
            and self._world_state is world_state
            and int(self._player_count) == int(player_count)
        ):
            return runner, session

        detail_preset = 5
        gore_disabled = 0
        config = self._world.config
        if config is not None:
            detail_preset = config.detail_preset
            gore_disabled = config.gore_disabled

        session = DeterministicSession(
            world=world_state,
            world_size=float(self._world.world_size),
            damage_scale_by_type=self._world.sim_world.damage_scale_by_type,
            fx_queue=self._world.render_resources.fx_queue,
            fx_queue_rotated=self._world.render_resources.fx_queue_rotated,
            game_mode=self._game_mode,
            detail_preset=int(detail_preset),
            gore_disabled=int(gore_disabled),
            game_tune_started=bool(self._world.sim_world.game_tune_started),
            demo_mode_active=bool(self._world.demo_mode_active),
            auto_pick_perks=False,
            perk_progression_enabled=False,
            apply_world_dt_steps=True,
            clear_fx_queues_each_tick=False,
        )
        provider = LocalInputProvider(
            player_count=int(player_count),
            build_inputs=self._build_inputs,
        )
        runner = TickRunner(
            session=session,
            input_provider=provider,
            config=TickRunnerConfig(),
        )
        self._session = session
        self._runner = runner
        self._world_state = world_state
        self._player_count = int(player_count)
        self._clock = FixedStepClock(tick_rate=int(self._tick_rate))
        self._frame_index = 0
        self._next_tick_index = 0
        return runner, session

    def _apply_batch(
        self,
        *,
        batch: TickBatchResult,
        session: DeterministicSession,
    ) -> int:
        ticks_applied = 0
        for result in batch.completed_results:
            payload = result.payload
            if payload is None:
                continue
            tick = cast(DeterministicSessionTick, payload)
            step = tick.step
            self._world.sim_world.apply_step_metadata(
                events=step.events,
                presentation=step.presentation,
                command_hash=str(step.command_hash),
                dt_sim=float(step.dt_sim),
                game_tune_started=bool(session.game_tune_started),
            )
            self._world.sync_audio_bridge_state()
            self._world.audio_bridge.apply_plan(
                plan=step.presentation,
                apply_audio=True,
            )
            self._world.update_camera(float(step.dt_sim))
            ticks_applied += 1
        return int(ticks_applied)

    def advance_frame(self, dt: float) -> int:
        if not self._world.sim_world.players:
            return 0
        self._world.sync_audio_bridge_state()
        self._world.terrain_runtime.process_pending()
        runner, session = self._ensure_runner()
        session.demo_mode_active = bool(self._world.demo_mode_active)
        dt = float(dt)
        ticks_requested = int(self._clock.advance(dt))
        self._frame_index = int(self._frame_index) + 1
        runner.begin_frame(
            FrameContext(
                dt_seconds=float(dt),
                tick_dt_seconds=float(self._clock.dt_tick),
                frame_index=int(self._frame_index),
                candidate_ticks=max(0, int(ticks_requested)),
                is_networked=False,
                is_replay=False,
            ),
        )
        batch = runner.advance_ticks(
            start_tick=int(self._next_tick_index),
            ticks_requested=max(0, int(ticks_requested)),
            tick_dt=float(self._clock.dt_tick),
        )
        self._next_tick_index = int(batch.next_tick_index)
        if batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
            unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
            if unconsumed_ticks > 0:
                self._clock.accum += float(unconsumed_ticks) * float(self._clock.dt_tick)
        return self._apply_batch(
            batch=batch,
            session=session,
        )
