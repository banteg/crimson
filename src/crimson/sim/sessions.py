from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import PlayerInput
from .step_pipeline import DeterministicStepResult, run_deterministic_step, time_scale_reflex_boost_bonus
from .world_state import WorldState


@dataclass(slots=True)
class DeterministicSessionTick:
    step: DeterministicStepResult
    elapsed_ms: float
    rng_marks: dict[str, int]
    creature_count_world_step: int


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
    auto_pick_perks: bool = False
    demo_mode_active: bool = False
    perk_progression_enabled: bool = True
    clear_fx_queues_each_tick: bool = False
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown_ms: float = 0.0

    def step_tick(
        self,
        *,
        dt_frame: float,
        dt_frame_ms_i32: int | None = None,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> DeterministicSessionTick:
        dt_frame = float(dt_frame)
        state = self.world.state
        dt_sim = time_scale_reflex_boost_bonus(
            reflex_boost_timer=float(state.bonuses.reflex_boost),
            time_scale_active=bool(state.time_scale_active),
            dt=float(dt_frame),
        )
        dt_sim_ms = float(dt_sim) * 1000.0
        if dt_frame_ms_i32 is not None and int(dt_frame_ms_i32) > 0:
            # Use captured integer ms for native cadence counters when available,
            # then apply reflex scaling with integer semantics.
            base_dt_ms_i32 = int(dt_frame_ms_i32)
            if bool(state.time_scale_active) and float(dt_frame) > 0.0:
                scale = float(dt_sim) / float(dt_frame)
                dt_sim_ms = float(max(0, int(float(base_dt_ms_i32) * float(scale))))
            else:
                dt_sim_ms = float(base_dt_ms_i32)
        elapsed_before_ms = float(self.elapsed_ms)

        rng_marks: dict[str, int] = {"before_world_step": int(state.rng.state)}
        step = run_deterministic_step(
            world=self.world,
            dt_frame=float(dt_frame),
            dt_frame_ms_i32=(int(dt_frame_ms_i32) if dt_frame_ms_i32 is not None else None),
            inputs=inputs,
            world_size=float(self.world_size),
            damage_scale_by_type=self.damage_scale_by_type,
            detail_preset=int(self.detail_preset),
            fx_toggle=int(self.fx_toggle),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            auto_pick_perks=bool(self.auto_pick_perks),
            game_mode=int(GameMode.SURVIVAL),
            demo_mode_active=bool(self.demo_mode_active),
            perk_progression_enabled=bool(self.perk_progression_enabled),
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

        creature_count_world_step = sum(1 for creature in self.world.creatures.entries if creature.active)
        rng_marks["after_world_step"] = int(state.rng.state)

        # Native `survival_update` runs after gameplay world updates:
        # - it observes current player XP/level (post-kill award),
        # - it computes spawn interval from the pre-increment survival elapsed timer.
        player_level = self.world.players[0].level if self.world.players else 1
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

        player_xp = self.world.players[0].experience if self.world.players else 0
        cooldown, wave_spawns = tick_survival_wave_spawns(
            self.spawn_cooldown_ms,
            dt_sim_ms,
            state.rng,
            player_count=len(self.world.players),
            survival_elapsed_ms=float(elapsed_before_ms),
            player_experience=int(player_xp),
            terrain_width=int(self.world_size),
            terrain_height=int(self.world_size),
        )
        self.spawn_cooldown_ms = cooldown
        self.world.creatures.spawn_inits(wave_spawns)
        rng_marks["after_wave_spawns"] = int(state.rng.state)
        self.world.creatures.finalize_post_render_lifecycle()
        self.elapsed_ms = float(elapsed_before_ms) + float(dt_sim_ms)

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
            creature_count_world_step=int(creature_count_world_step),
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

        creature_count_world_step = sum(1 for creature in self.world.creatures.entries if creature.active)
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
        self.world.creatures.finalize_post_render_lifecycle()

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
            creature_count_world_step=int(creature_count_world_step),
        )
