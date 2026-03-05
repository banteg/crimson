from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeAlias

import msgspec

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..gameplay import survival_update_weapon_handouts
from ..perks.selection import perk_selection_current_choices, perk_selection_pick
from ..quests.runtime import tick_quest_completion_transition
from ..quests.timeline import quest_spawn_table_empty, tick_quest_mode_spawns
from ..quests.types import SpawnEntry
from .input import PlayerInput
from .input_providers import GameCommand, PerkMenuOpenCommand, PerkPickCommand
from .step_pipeline import (
    DeterministicStepResult,
    StepPipelineOptions,
    run_deterministic_step,
    time_scale_reflex_boost_factor,
)
from .timing import FrameTiming, zero_gate_active_from_state
from .world_state import WorldState

# ---------------------------------------------------------------------------
# Tick result types
# ---------------------------------------------------------------------------

class DeterministicSessionTick(msgspec.Struct):
    step: DeterministicStepResult
    elapsed_ms: float
    rng_marks: dict[str, int]
    creature_count_world_step: int



# ---------------------------------------------------------------------------
# Mid-/post-step hook system (spawn strategies)
# ---------------------------------------------------------------------------

class MidStepContext(msgspec.Struct, frozen=True):
    """Context passed to mid-step spawn hooks during deterministic stepping."""

    world: WorldState
    rng_marks: dict[str, int]
    elapsed_before_ms: float
    dt_sim_ms: float
    dt_raw_ms: float
    world_size: float

MidStepHook: TypeAlias = Callable[[MidStepContext], None]

class PostStepContext(msgspec.Struct, frozen=True):
    """Context passed to post-step hooks during deterministic stepping."""

    world: WorldState
    rng_marks: dict[str, int]
    step_result: DeterministicStepResult

PostStepHook: TypeAlias = Callable[[PostStepContext], None]

@dataclass
class SurvivalSpawnState:
    stage: int = 0
    spawn_cooldown_ms: float = 0.0

@dataclass
class RushSpawnState:
    spawn_cooldown_ms: float = 0.0

@dataclass
class QuestSpawnState:
    spawn_entries: tuple[SpawnEntry, ...] = ()
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0
    completed: bool = False
    play_hit_sfx: bool = False
    play_completion_music: bool = False

def survival_mid_step(ctx: MidStepContext, spawn: SurvivalSpawnState) -> None:
    state = ctx.world.state
    survival_update_weapon_handouts(
        state,
        ctx.world.players,
        survival_elapsed_ms=ctx.elapsed_before_ms,
    )

    player_level = ctx.world.players[0].level if ctx.world.players else 1
    stage, milestone_calls = advance_survival_spawn_stage(spawn.stage, player_level=int(player_level))
    spawn.stage = stage
    for call in milestone_calls:
        ctx.world.creatures.spawn_template(
            call.template_id,
            call.pos,
            float(call.heading),
            state.rng,
            rand=state.rng.rand,
        )
    ctx.rng_marks["after_stage_spawns"] = int(state.rng.state)

    player_xp = ctx.world.players[0].experience if ctx.world.players else 0
    cooldown, wave_spawns = tick_survival_wave_spawns(
        spawn.spawn_cooldown_ms,
        ctx.dt_sim_ms,
        state.rng,
        player_count=len(ctx.world.players),
        survival_elapsed_ms=ctx.elapsed_before_ms,
        player_experience=int(player_xp),
        terrain_width=int(ctx.world_size),
        terrain_height=int(ctx.world_size),
    )
    spawn.spawn_cooldown_ms = cooldown
    ctx.world.creatures.spawn_inits(wave_spawns)
    ctx.rng_marks["after_wave_spawns"] = int(state.rng.state)

def rush_mid_step(ctx: MidStepContext, spawn: RushSpawnState) -> None:
    state = ctx.world.state
    cooldown, spawns = tick_rush_mode_spawns(
        spawn.spawn_cooldown_ms,
        ctx.dt_raw_ms,
        state.rng,
        player_count=len(ctx.world.players),
        survival_elapsed_ms=int(ctx.elapsed_before_ms),
        terrain_width=float(ctx.world_size),
        terrain_height=float(ctx.world_size),
    )
    spawn.spawn_cooldown_ms = cooldown
    ctx.world.creatures.spawn_inits(spawns)
    ctx.rng_marks["after_rush_spawns"] = int(state.rng.state)

def quest_post_step(ctx: PostStepContext, spawn: QuestSpawnState) -> None:
    state = ctx.world.state
    dt_ms = float(ctx.step_result.timing.dt_ms_i32)
    creatures_none_active = not any(c.active for c in ctx.world.creatures.entries)

    entries, timeline_ms, creatures_none_active, no_creatures_timer_ms, spawns = tick_quest_mode_spawns(
        spawn.spawn_entries,
        quest_spawn_timeline_ms=spawn.spawn_timeline_ms,
        frame_dt_ms=dt_ms,
        terrain_width=ctx.world.spawn_env.terrain_width,
        creatures_none_active=creatures_none_active,
        no_creatures_timer_ms=spawn.no_creatures_timer_ms,
    )
    spawn.spawn_entries = entries
    spawn.spawn_timeline_ms = float(timeline_ms)
    spawn.no_creatures_timer_ms = float(no_creatures_timer_ms)
    spawn_table_empty_now = quest_spawn_table_empty(spawn.spawn_entries)

    if not bool(state.demo_mode_active) and creatures_none_active and spawn_table_empty_now:
        state.bonuses.reflex_boost = 0.0
        state.time_scale_active = False

    for call in spawns:
        ctx.world.creatures.spawn_template(
            call.template_id,
            call.pos,
            float(call.heading),
            state.rng,
            rand=state.rng.rand,
        )
    ctx.rng_marks["after_quest_spawns"] = int(state.rng.state)

    any_alive_after = any(player.health > 0.0 for player in ctx.world.players)
    if any_alive_after:
        completion_ms, completed, play_hit_sfx, play_completion_music = tick_quest_completion_transition(
            spawn.completion_transition_ms,
            frame_dt_ms=dt_ms,
            creatures_none_active=creatures_none_active,
            spawn_table_empty=spawn_table_empty_now,
        )
        spawn.completion_transition_ms = float(completion_ms)
        spawn.completed = bool(completed)
        spawn.play_hit_sfx = bool(play_hit_sfx)
        spawn.play_completion_music = bool(play_completion_music)
    else:
        spawn.completion_transition_ms = -1.0
        spawn.completed = False
        spawn.play_hit_sfx = False
        spawn.play_completion_music = False

def rush_input_transform(inputs: list[PlayerInput]) -> list[PlayerInput]:
    return [
        msgspec.structs.replace(inp, reload_pressed=False) if inp.reload_pressed else inp
        for inp in inputs
    ]

# ---------------------------------------------------------------------------
# Shared timing helper
# ---------------------------------------------------------------------------

def _session_timing(state: object, dt: float) -> FrameTiming:
    """Compute frame timing from world state. Used by all session types."""
    return FrameTiming.compute(
        dt,
        time_scale_active_entry=bool(state.time_scale_active),  # type: ignore[union-attr]
        time_scale_factor=time_scale_reflex_boost_factor(
            reflex_boost_timer=float(state.bonuses.reflex_boost),  # type: ignore[union-attr]
            time_scale_active=bool(state.time_scale_active),  # type: ignore[union-attr]
        ),
        zero_gate_active=zero_gate_active_from_state(
            demo_mode_active=bool(state.demo_mode_active),  # type: ignore[union-attr]
        ),
    )

# ---------------------------------------------------------------------------
# Unified deterministic session (replaces Survival/Rush/Tutorial/Typo/WorldTick)
# ---------------------------------------------------------------------------

class DeterministicSession(msgspec.Struct):
    # Core state
    world: WorldState
    world_size: float
    damage_scale_by_type: dict[int, float]
    fx_queue: FxQueue
    fx_queue_rotated: FxQueueRotated

    # Mode identity
    game_mode: GameMode
    perk_progression_enabled: bool

    # Sim config
    detail_preset: int = 5
    gore_disabled: int = 0
    game_tune_started: bool = False
    demo_mode_active: bool = False
    auto_pick_perks: bool = False
    apply_world_dt_steps: bool = True
    defer_camera_shake_update: bool = False
    clear_fx_queues_each_tick: bool = False
    finalize_post_render_lifecycle: bool = False
    elapsed_uses_raw_dt: bool = False

    # Mutable timing
    elapsed_ms: float = 0.0

    # Optional hooks (provided by modes / callers)
    mid_step_hook: MidStepHook | None = None
    post_step_hook: PostStepHook | None = None
    before_step_hook: Callable[[], None] | None = None
    input_transform: Callable[[list[PlayerInput]], list[PlayerInput]] | None = None

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _session_timing(self.world.state, dt)

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
        commands: list[GameCommand] | None = None,
    ) -> DeterministicSessionTick:
        if self.before_step_hook is not None:
            self.before_step_hook()

        tick_inputs = inputs
        if tick_inputs is not None and self.input_transform is not None:
            tick_inputs = self.input_transform(tick_inputs)

        post_apply_sfx_keys: list[str] = []
        for cmd in (commands or ()):
            match cmd:
                case PerkPickCommand(choice_index=ci):
                    picked = perk_selection_pick(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        ci,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                        dt=float(timing.dt_sim),
                        creatures=self.world.creatures.entries,
                    )
                    if picked is not None:
                        # Eagerly regenerate choices so the RNG sequence matches
                        # the recording path (pick sets choices_dirty=True).
                        perk_selection_current_choices(
                            self.world.state,
                            self.world.players,
                            self.world.state.perk_selection,
                            game_mode=self.game_mode,
                            player_count=len(self.world.players),
                        )
                        post_apply_sfx_keys.append("sfx_ui_bonus")
                case PerkMenuOpenCommand():
                    perk_selection_current_choices(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                    )
                case _:
                    raise RuntimeError(f"unhandled command type: {type(cmd).__name__}")

        state = self.world.state
        dt_sim_ms = float(timing.dt_sim_ms_i32)
        dt_raw_ms = float(timing.dt_ms_i32)
        elapsed_before_ms = self.elapsed_ms

        rng_marks: dict[str, int] = {}
        if commands:
            rng_marks["after_commands"] = int(state.rng.state)
        rng_marks["before_world_step"] = int(state.rng.state)

        hook: Callable[[], None] | None = None
        if self.mid_step_hook is not None:
            ctx = MidStepContext(
                world=self.world,
                rng_marks=rng_marks,
                elapsed_before_ms=elapsed_before_ms,
                dt_sim_ms=dt_sim_ms,
                dt_raw_ms=dt_raw_ms,
                world_size=self.world_size,
            )
            _mid = self.mid_step_hook
            hook = lambda: _mid(ctx)  # noqa: E731

        step = run_deterministic_step(
            world=self.world,
            timing=timing,
            options=StepPipelineOptions(
                world_size=self.world_size,
                damage_scale_by_type=self.damage_scale_by_type,
                detail_preset=self.detail_preset,
                gore_disabled=self.gore_disabled,
                auto_pick_perks=self.auto_pick_perks,
                game_mode=self.game_mode,
                demo_mode_active=self.demo_mode_active,
                perk_progression_enabled=self.perk_progression_enabled,
                game_tune_started=self.game_tune_started,
            ),
            apply_world_dt_steps=self.apply_world_dt_steps,
            inputs=tick_inputs,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            defer_camera_shake_update=self.defer_camera_shake_update,
            mid_step_hook=hook,
            rng_marks_out=rng_marks,
            trace_presentation_rng=trace_rng,
        )
        if post_apply_sfx_keys:
            step = msgspec.structs.replace(
                step,
                post_apply_sfx_keys=tuple(str(key) for key in post_apply_sfx_keys),
            )
        if step.presentation.trigger_game_tune:
            self.game_tune_started = True

        if self.post_step_hook is not None:
            self.post_step_hook(
                PostStepContext(
                    world=self.world,
                    rng_marks=rng_marks,
                    step_result=step,
                ),
            )

        if self.clear_fx_queues_each_tick:
            self.fx_queue.clear()
            self.fx_queue_rotated.clear()

        creature_count_world_step = sum(1 for c in self.world.creatures.entries if c.active)
        rng_marks["after_world_step"] = int(state.rng.state)
        rng_marks["after_camera_update"] = int(rng_marks.get("ws_after_camera_update", state.rng.state))

        if self.finalize_post_render_lifecycle:
            self.world.creatures.finalize_post_render_lifecycle()

        dt_elapsed = dt_raw_ms if self.elapsed_uses_raw_dt else dt_sim_ms
        self.elapsed_ms = elapsed_before_ms + dt_elapsed

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=self.elapsed_ms,
            rng_marks=rng_marks,
            creature_count_world_step=creature_count_world_step,
        )
