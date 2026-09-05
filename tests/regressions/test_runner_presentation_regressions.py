from __future__ import annotations

from pathlib import Path

from crimson.creatures.spawn import SpawnId
from crimson.game_modes import GameMode
from crimson.sim.clock import FixedStepClock
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputStatus, LocalInputProvider, LocalInputRuntime
from crimson.sim.sessions import DeterministicSession
from crimson.sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from tests.support.builders.input_providers import StaticLocalInputRuntime
from tests.support.world_runtime import WorldRuntimeHost


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def _build_runner(
    world: WorldRuntimeHost,
    *,
    input_runtime: LocalInputRuntime,
) -> tuple[DeterministicSession, TickRunner]:
    session = DeterministicSession(
        world=world.sim_world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world.sim_world.damage_scale_by_type,
        game_mode=GameMode.SURVIVAL,
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=bool(world.sim_world.game_tune_started),
        demo_mode_active=False,
        perk_progression_enabled=False,
        apply_world_dt_steps=True,
    )
    provider = LocalInputProvider(
        player_count=len(world.sim_world.players),
        runtime=input_runtime,
    )
    runner = TickRunner(
        session=session,
        input_provider=provider,
        config=TickRunnerConfig(),
    )
    return session, runner


def _apply_batch(
    world: WorldRuntimeHost,
    *,
    session: DeterministicSession,
    batch: TickBatchResult,
) -> list[int]:
    applied_ticks: list[int] = []
    for result in batch.completed_results:
        step = result.payload
        world.sim_world.apply_step_metadata(
            events=step.events,
            presentation=step.presentation,
            dt_sim=float(step.dt_sim),
            game_tune_started=bool(session.game_tune_started),
        )
        world.sync_audio_bridge_state()
        world.audio_bridge.apply_plan(
            plan=step.presentation,
            apply_audio=True,
        )
        world.update_camera(step.presentation.camera)
        world.render_resources.consume_terrain_fx_batch(step.presentation.terrain_fx)
        applied_ticks.append(int(result.source_tick.tick_index))
    return applied_ticks


def _advance_with_clock(
    *,
    runner: TickRunner,
    clock: FixedStepClock,
    start_tick: int,
    frame_index: int,
    dt_seconds: float,
) -> tuple[TickBatchResult, int, int]:
    ticks_requested = int(clock.advance(float(dt_seconds)))
    frame_index = int(frame_index) + 1
    runner.begin_frame(
        FrameContext(
            dt_seconds=float(dt_seconds),
            tick_dt_seconds=float(clock.dt_tick),
            frame_index=int(frame_index),
            candidate_ticks=max(0, int(ticks_requested)),
            is_replay=False,
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


def test_runner_path_projectile_hits_enqueue_decals() -> None:
    world = WorldRuntimeHost(assets_dir=_assets_dir())
    player = world.sim_world.players[0]
    target = player.pos.offset(dx=48.0)
    world.sim_world.creatures.spawn_template(
        SpawnId.ZOMBIE_SMALL_WHITE_42,
        target,
        3.14,
        world.sim_world.state.rng,
    )

    session, runner = _build_runner(
        world,
        input_runtime=StaticLocalInputRuntime(
            inputs=(PlayerInput(aim=target, fire_down=True, fire_pressed=True),),
        ),
    )
    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0

    for _ in range(120):
        batch, next_tick_index, frame_index = _advance_with_clock(
            runner=runner,
            clock=clock,
            start_tick=next_tick_index,
            frame_index=frame_index,
            dt_seconds=1.0 / 60.0,
        )
        if any(not result.payload.presentation.terrain_fx.is_empty() for result in batch.completed_results):
            break
        _apply_batch(world, session=session, batch=batch)

    assert any(not result.payload.presentation.terrain_fx.is_empty() for result in batch.completed_results)


def test_runner_multi_tick_batch_apply_order_is_deterministic() -> None:
    def _advance_once() -> tuple[list[int], list[int]]:
        world = WorldRuntimeHost(assets_dir=_assets_dir())
        session, runner = _build_runner(
            world,
            input_runtime=StaticLocalInputRuntime(inputs=(PlayerInput(),)),
        )
        clock = FixedStepClock(tick_rate=60)
        frame_index = 0
        next_tick_index = 0
        batch, next_tick_index, frame_index = _advance_with_clock(
            runner=runner,
            clock=clock,
            start_tick=next_tick_index,
            frame_index=frame_index,
            dt_seconds=(3.0 / 60.0) + 1e-9,
        )
        order = _apply_batch(world, session=session, batch=batch)
        tick_indices = [int(result.source_tick.tick_index) for result in batch.completed_results]
        return order, tick_indices

    order_a, indices_a = _advance_once()
    order_b, indices_b = _advance_once()

    assert order_a == [0, 1, 2]
    assert order_b == [0, 1, 2]
    assert indices_a == indices_b
