from __future__ import annotations

from typing import Protocol

from grim.config import CrimsonConfig

from ..game_modes import GameMode
from ..world import AudioBridge, RenderResources, SimWorldState, TerrainRuntime
from .input import PlayerInput
from .step_pipeline import StepPipelineOptions, run_deterministic_step, time_scale_reflex_boost_factor
from .timing import FrameTiming, zero_gate_active_from_state
from .world_state import ProjectileHit


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
