from __future__ import annotations

from pathlib import Path
from typing import cast

from crimson.creatures.spawn import SpawnId
from crimson.game_modes import GameMode
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import LocalInputProvider
from crimson.sim.sessions import DeterministicSession, DeterministicSessionTick
from crimson.sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from tests.world_runtime import WorldRuntimeHost


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def _build_runner(
    world: WorldRuntimeHost,
    *,
    build_inputs,
) -> tuple[DeterministicSession, TickRunner]:
    session = DeterministicSession(
        world=world.sim_world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world.sim_world.damage_scale_by_type,
        fx_queue=world.render_resources.fx_queue,
        fx_queue_rotated=world.render_resources.fx_queue_rotated,
        game_mode=GameMode.SURVIVAL,
        detail_preset=5,
        gore_disabled=0,
        game_tune_started=bool(world.sim_world.game_tune_started),
        demo_mode_active=False,
        auto_pick_perks=False,
        perk_progression_enabled=False,
        apply_world_dt_steps=True,
        clear_fx_queues_each_tick=False,
    )
    provider = LocalInputProvider(
        player_count=len(world.sim_world.players),
        build_inputs=build_inputs,
    )
    runner = TickRunner(
        session=session,
        input_provider=provider,
        config=TickRunnerConfig(tick_rate=60),
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
        payload = result.payload
        if payload is None:
            continue
        tick = cast(DeterministicSessionTick, payload)
        step = tick.step
        world.sim_world.apply_step_metadata(
            events=step.events,
            presentation=step.presentation,
            command_hash=str(step.command_hash),
            dt_sim=float(step.dt_sim),
            game_tune_started=bool(session.game_tune_started),
        )
        world.sync_audio_bridge_state()
        world.audio_bridge.apply_plan(
            plan=step.presentation,
            apply_audio=True,
        )
        world.update_camera(float(step.dt_sim))
        applied_ticks.append(int(result.tick_index))
    return applied_ticks


def test_runner_path_projectile_hits_enqueue_decals() -> None:
    world = WorldRuntimeHost(assets_dir=_assets_dir())
    player = world.sim_world.players[0]
    target = player.pos.offset(dx=48.0)
    world.sim_world.creatures.spawn_template(
        int(SpawnId.ZOMBIE_CONST_GREY_42),
        target,
        3.14,
        world.sim_world.state.rng,
        rand=world.sim_world.state.rng.rand,
    )

    session, runner = _build_runner(
        world,
        build_inputs=lambda frame_ctx: [
            PlayerInput(
                aim=target,
                fire_down=True,
                fire_pressed=True,
            ),
        ],
    )

    for _ in range(120):
        batch = runner.advance_frame(1.0 / 60.0)
        _apply_batch(world, session=session, batch=batch)
        if int(world.render_resources.fx_queue.count) > 0:
            break

    assert int(world.render_resources.fx_queue.count) > 0


def test_runner_multi_tick_batch_apply_order_is_deterministic() -> None:
    def _advance_once() -> tuple[list[int], list[str]]:
        world = WorldRuntimeHost(assets_dir=_assets_dir())
        session, runner = _build_runner(
            world,
            build_inputs=lambda frame_ctx: [PlayerInput()],
        )
        batch = runner.advance_frame((3.0 / 60.0) + 1e-9)
        order = _apply_batch(world, session=session, batch=batch)
        command_hashes = [str(result.command_hash) for result in batch.completed_results]
        return order, command_hashes

    order_a, hashes_a = _advance_once()
    order_b, hashes_b = _advance_once()

    assert order_a == [0, 1, 2]
    assert order_b == [0, 1, 2]
    assert hashes_a == hashes_b
