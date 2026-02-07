from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import PlayerInput
from .step_pipeline import DeterministicStepResult, run_deterministic_step
from .world_state import WorldState


@dataclass(slots=True)
class DeterministicSessionTick:
    step: DeterministicStepResult
    elapsed_ms: float
    rng_marks: dict[str, int]


@dataclass(slots=True)
class SurvivalDeterministicSession:
    world: WorldState
    world_size: float
    damage_scale_by_type: dict[int, float]
    fx_queue: FxQueue
    fx_queue_rotated: FxQueueRotated
    detail_preset: int = 5
    fx_toggle: int = 0
    game_tune_started: bool = False
    clear_fx_queues_each_tick: bool = False
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown_ms: float = 0.0

    def step_tick(
        self,
        *,
        dt_frame: float,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> DeterministicSessionTick:
        dt_frame = float(dt_frame)
        dt_frame_ms = float(dt_frame) * 1000.0
        self.elapsed_ms += float(dt_frame_ms)

        state = self.world.state
        player_level = self.world.players[0].level if self.world.players else 1
        player_xp = self.world.players[0].experience if self.world.players else 0

        rng_marks: dict[str, int] = {"before_world_step": int(state.rng.state)}
        step = run_deterministic_step(
            world=self.world,
            dt_frame=float(dt_frame),
            inputs=inputs,
            world_size=float(self.world_size),
            damage_scale_by_type=self.damage_scale_by_type,
            detail_preset=int(self.detail_preset),
            fx_toggle=int(self.fx_toggle),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            demo_mode_active=False,
            perk_progression_enabled=True,
            game_tune_started=bool(self.game_tune_started),
            rng_marks_out=rng_marks,
            trace_presentation_rng=bool(trace_rng),
        )
        if step.presentation.trigger_game_tune:
            self.game_tune_started = True

        if self.clear_fx_queues_each_tick:
            # Live gameplay clears terrain FX queues during render (`bake_fx_queues(clear=True)`).
            # Headless verification has no render pass, so clear explicitly per simulated tick.
            self.fx_queue.clear()
            self.fx_queue_rotated.clear()

        rng_marks["after_world_step"] = int(state.rng.state)

        stage, milestone_calls = advance_survival_spawn_stage(self.stage, player_level=int(player_level))
        self.stage = stage
        for call in milestone_calls:
            self.world.creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                state.rng,
                rand=state.rng.rand,
            )
        rng_marks["after_stage_spawns"] = int(state.rng.state)

        cooldown, wave_spawns = tick_survival_wave_spawns(
            self.spawn_cooldown_ms,
            dt_frame_ms,
            state.rng,
            player_count=len(self.world.players),
            survival_elapsed_ms=float(self.elapsed_ms),
            player_experience=int(player_xp),
            terrain_width=int(self.world_size),
            terrain_height=int(self.world_size),
        )
        self.spawn_cooldown_ms = cooldown
        self.world.creatures.spawn_inits(wave_spawns)
        rng_marks["after_wave_spawns"] = int(state.rng.state)

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
        )


@dataclass(slots=True)
class RushDeterministicSession:
    world: WorldState
    world_size: float
    damage_scale_by_type: dict[int, float]
    fx_queue: FxQueue
    fx_queue_rotated: FxQueueRotated
    detail_preset: int = 5
    fx_toggle: int = 0
    game_tune_started: bool = False
    clear_fx_queues_each_tick: bool = False
    enforce_loadout: Callable[[], None] | None = None
    elapsed_ms: float = 0.0
    spawn_cooldown_ms: float = 0.0

    def step_tick(
        self,
        *,
        dt_frame: float,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> DeterministicSessionTick:
        dt_frame = float(dt_frame)
        dt_frame_ms = float(dt_frame) * 1000.0
        self.elapsed_ms += float(dt_frame_ms)

        if self.enforce_loadout is not None:
            self.enforce_loadout()

        state = self.world.state
        rng_marks: dict[str, int] = {"before_world_step": int(state.rng.state)}
        step = run_deterministic_step(
            world=self.world,
            dt_frame=float(dt_frame),
            inputs=inputs,
            world_size=float(self.world_size),
            damage_scale_by_type=self.damage_scale_by_type,
            detail_preset=int(self.detail_preset),
            fx_toggle=int(self.fx_toggle),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            auto_pick_perks=False,
            game_mode=int(GameMode.RUSH),
            demo_mode_active=False,
            perk_progression_enabled=False,
            game_tune_started=bool(self.game_tune_started),
            rng_marks_out=rng_marks,
            trace_presentation_rng=bool(trace_rng),
        )
        if step.presentation.trigger_game_tune:
            self.game_tune_started = True

        if self.clear_fx_queues_each_tick:
            # Live gameplay clears terrain FX queues during render (`bake_fx_queues(clear=True)`).
            # Headless verification has no render pass, so clear explicitly per simulated tick.
            self.fx_queue.clear()
            self.fx_queue_rotated.clear()

        rng_marks["after_world_step"] = int(state.rng.state)

        cooldown, spawns = tick_rush_mode_spawns(
            self.spawn_cooldown_ms,
            dt_frame_ms,
            state.rng,
            player_count=len(self.world.players),
            survival_elapsed_ms=int(self.elapsed_ms),
            terrain_width=float(self.world_size),
            terrain_height=float(self.world_size),
        )
        self.spawn_cooldown_ms = cooldown
        self.world.creatures.spawn_inits(spawns)
        rng_marks["after_rush_spawns"] = int(state.rng.state)

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
        )
