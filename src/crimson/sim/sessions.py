from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeAlias

import msgspec

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import survival_update_weapon_handouts
from ..quests.runtime import tick_quest_completion_transition
from ..quests.timeline import quest_spawn_table_empty, tick_quest_mode_spawns
from ..quests.types import SpawnEntry
from .input import PlayerInput
from .step_pipeline import (
    DeterministicStepResult,
    StepPipelineOptions,
    run_deterministic_step,
    time_scale_reflex_boost_factor,
)
from .timing import FrameTiming
from .world_state import WorldState


class DeterministicSessionTick(msgspec.Struct):
    step: DeterministicStepResult
    elapsed_ms: float
    rng_marks: dict[str, int]
    creature_count_world_step: int


class SurvivalDeterministicSession(msgspec.Struct):
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
    apply_world_dt_steps: bool = True
    clear_fx_queues_each_tick: bool = False
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown_ms: float = 0.0

    def timing_for_dt(self, dt_frame: float) -> FrameTiming:
        state = self.world.state
        return FrameTiming.compute(
            float(dt_frame),
            time_scale_active_entry=bool(state.time_scale_active),
            time_scale_factor=time_scale_reflex_boost_factor(
                reflex_boost_timer=float(state.bonuses.reflex_boost),
                time_scale_active=bool(state.time_scale_active),
            ),
            zero_gate_active=False,
        )

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> DeterministicSessionTick:
        state = self.world.state
        dt_sim_ms = float(timing.dt_sim_ms_i32)
        elapsed_before_ms = float(self.elapsed_ms)

        rng_marks: dict[str, int] = {"before_world_step": int(state.rng.state)}
        dt_sim_ms_value = float(dt_sim_ms)

        def _mid_step_spawns() -> None:
            # Native `survival_update` runs after gameplay world updates:
            # - it observes current player XP/level (post-kill award),
            # - it computes spawn interval from the pre-increment survival elapsed timer.
            survival_update_weapon_handouts(
                state,
                self.world.players,
                survival_elapsed_ms=float(elapsed_before_ms),
            )

            player_level = self.world.players[0].level if self.world.players else 1
            stage, milestone_calls = advance_survival_spawn_stage(self.stage, player_level=int(player_level))
            self.stage = stage
            for call in milestone_calls:
                self.world.creatures.spawn_template(
                    call.template_id,
                    call.pos,
                    float(call.heading),
                    state.rng,
                    rand=state.rng.rand,
                )
            rng_marks["after_stage_spawns"] = int(state.rng.state)

            player_xp = self.world.players[0].experience if self.world.players else 0
            cooldown, wave_spawns = tick_survival_wave_spawns(
                self.spawn_cooldown_ms,
                dt_sim_ms_value,
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

        step = run_deterministic_step(
            world=self.world,
            timing=timing,
            options=StepPipelineOptions(
                world_size=float(self.world_size),
                damage_scale_by_type=self.damage_scale_by_type,
                detail_preset=int(self.detail_preset),
                fx_toggle=int(self.fx_toggle),
                auto_pick_perks=bool(self.auto_pick_perks),
                game_mode=int(GameMode.SURVIVAL),
                demo_mode_active=bool(self.demo_mode_active),
                perk_progression_enabled=bool(self.perk_progression_enabled),
                game_tune_started=bool(self.game_tune_started),
            ),
            apply_world_dt_steps=bool(self.apply_world_dt_steps),
            inputs=inputs,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            defer_camera_shake_update=False,
            mid_step_hook=_mid_step_spawns,
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
        rng_marks["after_camera_update"] = int(rng_marks.get("ws_after_camera_update", state.rng.state))
        self.world.creatures.finalize_post_render_lifecycle()
        self.elapsed_ms = float(elapsed_before_ms) + float(dt_sim_ms)

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
            creature_count_world_step=int(creature_count_world_step),
        )


class RushDeterministicSession(msgspec.Struct):
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
    elapsed_ms: int = 0
    spawn_cooldown_ms: float = 0.0

    def timing_for_dt(self, dt_frame: float) -> FrameTiming:
        state = self.world.state
        return FrameTiming.compute(
            float(dt_frame),
            time_scale_active_entry=bool(state.time_scale_active),
            time_scale_factor=time_scale_reflex_boost_factor(
                reflex_boost_timer=float(state.bonuses.reflex_boost),
                time_scale_active=bool(state.time_scale_active),
            ),
            zero_gate_active=False,
        )

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> DeterministicSessionTick:
        normalized_inputs = inputs
        if inputs is not None:
            normalized_inputs = [
                (msgspec.structs.replace(player_input, reload_pressed=False) if bool(player_input.reload_pressed) else player_input)
                for player_input in inputs
            ]

        dt_ms_i32 = int(timing.dt_ms_i32)
        if dt_ms_i32 < 1:
            dt_ms_i32 = 1
        dt_frame_ms = float(dt_ms_i32)
        elapsed_before_ms = int(self.elapsed_ms)

        if self.enforce_loadout is not None:
            self.enforce_loadout()

        state = self.world.state
        rng_marks: dict[str, int] = {"before_world_step": int(state.rng.state)}

        def _mid_step_spawns() -> None:
            # Native rush mode (`rush_mode_update`) consumes integer millisecond counters.
            # It reads survival_elapsed_ms before the frame-loop increments it.
            cooldown, spawns = tick_rush_mode_spawns(
                self.spawn_cooldown_ms,
                dt_frame_ms,
                state.rng,
                player_count=len(self.world.players),
                survival_elapsed_ms=int(elapsed_before_ms),
                terrain_width=float(self.world_size),
                terrain_height=float(self.world_size),
            )
            self.spawn_cooldown_ms = cooldown
            self.world.creatures.spawn_inits(spawns)
            rng_marks["after_rush_spawns"] = int(state.rng.state)

        step = run_deterministic_step(
            world=self.world,
            timing=timing,
            options=StepPipelineOptions(
                world_size=float(self.world_size),
                damage_scale_by_type=self.damage_scale_by_type,
                detail_preset=int(self.detail_preset),
                fx_toggle=int(self.fx_toggle),
                auto_pick_perks=False,
                game_mode=int(GameMode.RUSH),
                demo_mode_active=False,
                perk_progression_enabled=False,
                game_tune_started=bool(self.game_tune_started),
            ),
            inputs=normalized_inputs,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            defer_camera_shake_update=False,
            mid_step_hook=_mid_step_spawns,
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
        rng_marks["after_camera_update"] = int(rng_marks.get("ws_after_camera_update", state.rng.state))
        self.world.creatures.finalize_post_render_lifecycle()
        self.elapsed_ms = int(self.elapsed_ms) + int(dt_ms_i32)

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
            creature_count_world_step=int(creature_count_world_step),
        )


class QuestDeterministicSessionTick(msgspec.Struct):
    step: DeterministicStepResult
    elapsed_ms: float
    rng_marks: dict[str, int]
    creature_count_world_step: int
    spawn_timeline_ms: float
    no_creatures_timer_ms: float
    completion_transition_ms: float
    completed: bool
    play_hit_sfx: bool
    play_completion_music: bool


class QuestDeterministicSession(msgspec.Struct):
    world: WorldState
    world_size: float
    damage_scale_by_type: dict[int, float]
    fx_queue: FxQueue
    fx_queue_rotated: FxQueueRotated
    spawn_entries: tuple[SpawnEntry, ...] = ()
    detail_preset: int = 5
    fx_toggle: int = 0
    game_tune_started: bool = False
    apply_world_dt_steps: bool = True
    clear_fx_queues_each_tick: bool = False
    finalize_post_render_lifecycle_each_tick: bool = True
    elapsed_ms: float = 0.0
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0

    def timing_for_dt(self, dt_frame: float) -> FrameTiming:
        state = self.world.state
        return FrameTiming.compute(
            float(dt_frame),
            time_scale_active_entry=bool(state.time_scale_active),
            time_scale_factor=time_scale_reflex_boost_factor(
                reflex_boost_timer=float(state.bonuses.reflex_boost),
                time_scale_active=bool(state.time_scale_active),
            ),
            zero_gate_active=False,
        )

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> QuestDeterministicSessionTick:
        dt_frame_ms = float(timing.dt_ms_i32)
        self.elapsed_ms += float(dt_frame_ms)

        state = self.world.state
        rng_marks: dict[str, int] = {"before_world_step": int(state.rng.state)}

        step = run_deterministic_step(
            world=self.world,
            timing=timing,
            options=StepPipelineOptions(
                world_size=float(self.world_size),
                damage_scale_by_type=self.damage_scale_by_type,
                detail_preset=int(self.detail_preset),
                fx_toggle=int(self.fx_toggle),
                auto_pick_perks=False,
                game_mode=int(GameMode.QUESTS),
                demo_mode_active=bool(state.demo_mode_active),
                perk_progression_enabled=True,
                game_tune_started=bool(self.game_tune_started),
            ),
            apply_world_dt_steps=bool(self.apply_world_dt_steps),
            inputs=inputs,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            defer_camera_shake_update=False,
            rng_marks_out=rng_marks,
            trace_presentation_rng=bool(trace_rng),
        )
        if step.presentation.trigger_game_tune:
            self.game_tune_started = True

        # Native `creatures_none_active` checks slot `active` flags only; corpses
        # still count as active until lifecycle finalization clears the slot.
        creatures_none_active = not any(creature.active for creature in self.world.creatures.entries)
        entries, timeline_ms, creatures_none_active, no_creatures_timer_ms, spawns = tick_quest_mode_spawns(
            self.spawn_entries,
            quest_spawn_timeline_ms=float(self.spawn_timeline_ms),
            frame_dt_ms=float(dt_frame_ms),
            terrain_width=float(self.world_size),
            creatures_none_active=bool(creatures_none_active),
            no_creatures_timer_ms=float(self.no_creatures_timer_ms),
        )
        self.spawn_entries = entries
        self.spawn_timeline_ms = float(timeline_ms)
        self.no_creatures_timer_ms = float(no_creatures_timer_ms)
        spawn_table_empty_now = quest_spawn_table_empty(self.spawn_entries)
        # Native quest_mode_update (0x004070e0) clears Reflex Boost while the
        # quest is idle-complete (no active creatures and no pending spawns).
        if (not bool(state.demo_mode_active)) and bool(creatures_none_active) and bool(spawn_table_empty_now):
            state.bonuses.reflex_boost = 0.0
            state.time_scale_active = False
        for call in spawns:
            self.world.creatures.spawn_template(
                call.template_id,
                call.pos,
                float(call.heading),
                state.rng,
                rand=state.rng.rand,
            )
        rng_marks["after_quest_spawns"] = int(state.rng.state)

        any_alive_after = any(player.health > 0.0 for player in self.world.players)
        completed = False
        play_hit_sfx = False
        play_completion_music = False
        if any_alive_after:
            completion_ms, completed, play_hit_sfx, play_completion_music = tick_quest_completion_transition(
                float(self.completion_transition_ms),
                frame_dt_ms=float(dt_frame_ms),
                creatures_none_active=bool(creatures_none_active),
                spawn_table_empty=bool(spawn_table_empty_now),
            )
            self.completion_transition_ms = float(completion_ms)
        else:
            self.completion_transition_ms = -1.0

        if self.clear_fx_queues_each_tick:
            # Live gameplay clears terrain FX queues during render (`bake_fx_queues(clear=True)`).
            # Headless verification has no render pass, so clear explicitly per simulated tick.
            self.fx_queue.clear()
            self.fx_queue_rotated.clear()

        creature_count_world_step = sum(1 for creature in self.world.creatures.entries if creature.active)
        rng_marks["after_world_step"] = int(state.rng.state)
        rng_marks["after_camera_update"] = int(rng_marks.get("ws_after_camera_update", state.rng.state))
        if bool(self.finalize_post_render_lifecycle_each_tick):
            self.world.creatures.finalize_post_render_lifecycle()

        return QuestDeterministicSessionTick(
            step=step,
            elapsed_ms=float(self.elapsed_ms),
            rng_marks=rng_marks,
            creature_count_world_step=int(creature_count_world_step),
            spawn_timeline_ms=float(self.spawn_timeline_ms),
            no_creatures_timer_ms=float(self.no_creatures_timer_ms),
            completion_transition_ms=float(self.completion_transition_ms),
            completed=bool(completed),
            play_hit_sfx=bool(play_hit_sfx),
            play_completion_music=bool(play_completion_music),
        )


DeterministicSessionStepTick: TypeAlias = DeterministicSessionTick | QuestDeterministicSessionTick


class DeterministicSession(Protocol):
    elapsed_ms: int | float

    def timing_for_dt(self, dt_frame: float) -> FrameTiming: ...

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> DeterministicSessionStepTick: ...
