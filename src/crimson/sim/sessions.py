from __future__ import annotations

import time

import msgspec

from grim.rand import CrandLike, RecordingCrand
from grim.sfx_map import SfxId

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..game_modes import GameMode
from ..gameplay import survival_update_weapon_handouts
from ..perks.availability import prepare_perk_availability
from ..perks.selection import (
    perk_selection_open_choices,
    perk_selection_pick,
)
from ..quests.runtime import tick_quest_completion_transition
from ..quests.timeline import quest_spawn_table_empty, tick_quest_mode_spawns
from ..quests.types import SpawnEntry
from ..rng_caller_static import RngCallerStatic
from ..tutorial.runtime import tutorial_before_step, tutorial_input_transform, tutorial_post_step
from ..typo.runtime import apply_typo_command, typo_before_step, typo_input_transform, typo_mid_step, typo_post_step
from ..weapon_runtime import weapon_assign_player
from ..weapon_runtime.availability import prepare_weapon_availability
from ..weapons import WeaponId
from .input import PlayerInput
from .input_frame import normalize_input_frame
from .input_providers import (
    GameCommand,
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    PerkPickCommand,
    ReplayPostludeOperation,
    ReplayPreludeOperation,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from .presentation_step import plan_world_presentation_step
from .step_pipeline import (
    DeterministicStepResult,
    PresentationRngTrace,
)
from .terrain_fx import TerrainFxScratch
from .timing import FrameTiming, reflex_boost_time_scale_factor
from .world_state import WorldMidStepRuntime, WorldState

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE
RUSH_FORCED_AMMO = 30.0

# ---------------------------------------------------------------------------
# Tick result types
# ---------------------------------------------------------------------------


class DeterministicSessionTick(msgspec.Struct):
    step: DeterministicStepResult
    elapsed_ms: float
    creature_count_world_step: int
    presentation_plan_ms: float = 0.0


# ---------------------------------------------------------------------------
# Mode runtime system
# ---------------------------------------------------------------------------


class MidStepContext(msgspec.Struct, frozen=True):
    """Context passed to mid-step spawn hooks during deterministic stepping."""

    world: WorldState
    elapsed_before_ms: float
    dt_sim_ms: float
    dt_raw_ms: float
    world_size: float


class PostStepContext(msgspec.Struct, frozen=True):
    """Context passed to post-step hooks during deterministic stepping."""

    world: WorldState
    step_result: DeterministicStepResult
    dt_sim_ms: float
    world_size: float
    detail_preset: int


class SurvivalSpawnState(msgspec.Struct):
    stage: int = 0
    spawn_cooldown_ms: float = 0.0


class RushSpawnState(msgspec.Struct):
    spawn_cooldown_ms: float = 0.0


class QuestSpawnState(msgspec.Struct):
    spawn_entries: tuple[SpawnEntry, ...] = ()
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0
    completed: bool = False
    play_hit_sfx: bool = False
    play_completion_music: bool = False


def enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if player.weapon.weapon_id != RUSH_WEAPON_ID:
            weapon_assign_player(player, RUSH_WEAPON_ID, state=world.state)
        # Native `rush_mode_update` forces assault rifle + 30 ammo every frame.
        player.weapon.ammo = float(RUSH_FORCED_AMMO)


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
        )

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


def quest_mid_step(ctx: MidStepContext, spawn: QuestSpawnState) -> None:
    # Native runs quest_mode_update with the other mode updates before render,
    # so quest spawns draw RNG ahead of the presentation pass, like the other
    # modes' mid-steps. The scaled dt keeps the timeline (the quest score), the
    # stall timer, and the completion transition slowed under Reflex Boost.
    state = ctx.world.state
    dt_ms = float(ctx.dt_sim_ms)
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
        )

    # Native quest_mode_update has no player-alive gate on the completion
    # transition: if the timer crosses 2500 ms while the death animation is
    # still playing, the quest completes despite the player dying.
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


def rush_input_transform(inputs: list[PlayerInput]) -> list[PlayerInput]:
    return [msgspec.structs.replace(inp, reload_pressed=False) if inp.reload_pressed else inp for inp in inputs]


class SessionModeRuntime(msgspec.Struct):
    def before_step(self) -> None:
        return None

    def needs_mid_step(self) -> bool:
        return False

    def transform_inputs(self, inputs: list[PlayerInput]) -> list[PlayerInput]:
        return inputs

    def mid_step(self, ctx: MidStepContext) -> None:
        _ = ctx

    def post_step(self, ctx: PostStepContext) -> None:
        _ = ctx


class SurvivalSessionRuntime(SessionModeRuntime):
    spawn: SurvivalSpawnState = msgspec.field(default_factory=SurvivalSpawnState)

    def needs_mid_step(self) -> bool:
        return True

    def mid_step(self, ctx: MidStepContext) -> None:
        survival_mid_step(ctx, self.spawn)


class RushSessionRuntime(SessionModeRuntime):
    world: WorldState
    spawn: RushSpawnState = msgspec.field(default_factory=RushSpawnState)

    def before_step(self) -> None:
        enforce_rush_loadout(self.world)

    def needs_mid_step(self) -> bool:
        return True

    def transform_inputs(self, inputs: list[PlayerInput]) -> list[PlayerInput]:
        return rush_input_transform(inputs)

    def mid_step(self, ctx: MidStepContext) -> None:
        rush_mid_step(ctx, self.spawn)


class QuestSessionRuntime(SessionModeRuntime):
    spawn: QuestSpawnState

    def needs_mid_step(self) -> bool:
        return True

    def mid_step(self, ctx: MidStepContext) -> None:
        quest_mid_step(ctx, self.spawn)


class TypoSessionRuntime(SessionModeRuntime):
    world: WorldState

    def before_step(self) -> None:
        typo_before_step(self.world)

    def needs_mid_step(self) -> bool:
        return True

    def transform_inputs(self, inputs: list[PlayerInput]) -> list[PlayerInput]:
        return typo_input_transform(self.world, inputs)

    def mid_step(self, ctx: MidStepContext) -> None:
        typo_mid_step(ctx)

    def post_step(self, ctx: PostStepContext) -> None:
        typo_post_step(ctx)


class TutorialSessionRuntime(SessionModeRuntime):
    world: WorldState

    def before_step(self) -> None:
        tutorial_before_step(self.world)

    def transform_inputs(self, inputs: list[PlayerInput]) -> list[PlayerInput]:
        return tutorial_input_transform(self.world, inputs)

    def post_step(self, ctx: PostStepContext) -> None:
        tutorial_post_step(ctx)


class _SessionWorldMidStepRuntime(WorldMidStepRuntime):
    mode_runtime: SessionModeRuntime
    ctx: MidStepContext

    def run_mid_step(self) -> None:
        self.mode_runtime.mid_step(self.ctx)


# ---------------------------------------------------------------------------
# Shared timing helper
# ---------------------------------------------------------------------------


def _session_timing(world: WorldState, dt: float, *, apply_world_dt_steps: bool) -> FrameTiming:
    """Compute frame timing from world state. Used by all session types."""
    state = world.state
    world_dt = world.world_dt_after_perk_steps(dt) if bool(apply_world_dt_steps) else float(dt)
    return FrameTiming.compute(
        dt,
        world_dt=world_dt,
        time_scale_active_entry=bool(state.time_scale_active),
        time_scale_factor=reflex_boost_time_scale_factor(
            reflex_boost_timer=float(state.bonuses.reflex_boost),
            time_scale_active=bool(state.time_scale_active),
        ),
        zero_gate_active=False,
    )


# ---------------------------------------------------------------------------
# Unified deterministic session (replaces Survival/Rush/Tutorial/Typo/WorldTick)
# ---------------------------------------------------------------------------


class DeterministicSession(msgspec.Struct):
    # Core state
    world: WorldState
    world_size: float
    damage_scale_by_type: dict[int, float]

    # Mode identity
    game_mode: GameMode
    perk_progression_enabled: bool

    # Sim config
    detail_preset: int = 5
    violence_disabled: int = 0
    game_tune_started: bool = False
    demo_mode_active: bool = False
    apply_world_dt_steps: bool = True
    defer_camera_shake_update: bool = False
    finalize_post_render_lifecycle: bool = False
    elapsed_uses_raw_dt: bool = False

    # Mutable timing
    elapsed_ms: float = 0.0
    terrain_fx: TerrainFxScratch = msgspec.field(default_factory=TerrainFxScratch)

    mode_runtime: SessionModeRuntime = msgspec.field(default_factory=SessionModeRuntime)

    def __post_init__(self) -> None:
        state = self.world.state
        state.game_mode = self.game_mode
        state.demo_mode_active = self.demo_mode_active
        prepare_weapon_availability(state)
        prepare_perk_availability(state)

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _session_timing(
            self.world,
            dt,
            apply_world_dt_steps=bool(self.apply_world_dt_steps),
        )

    def apply_replay_prelude(
        self,
        *,
        dt: float,
        operations: list[ReplayPreludeOperation],
    ) -> list[SfxId]:
        """Apply ordered between-tick replay operations outside the tick RNG trace."""

        post_apply_sfx: list[SfxId] = []
        for operation in operations:
            match operation:
                case GameFrameRngAdvanceOperation(frames=frames):
                    if int(frames) <= 0:
                        raise RuntimeError(
                            f"replay game_frame_rng_advance frames must be > 0, got {frames}",
                        )
                    for _ in range(int(frames)):
                        self.world.state.rng.rand_tagged(
                            RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED,
                        )
                case PerkPickCommand(choice_index=choice_index):
                    # Earlier prelude operations may change time scaling, so
                    # derive the native apply delta at this exact position in
                    # the ordered stream.
                    timing = self.timing_for_dt(dt)
                    picked = perk_selection_pick(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        choice_index,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                        dt=timing.dt_sim,
                        creatures=self.world.creatures.entries,
                        refresh_choices=False,
                    )
                    if picked is not None:
                        post_apply_sfx.append(SfxId.UI_BONUS)
                case PerkMenuOpenCommand():
                    perk_selection_open_choices(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                    )
                case _:
                    raise RuntimeError(f"unhandled replay prelude operation: {type(operation).__name__}")
        return post_apply_sfx

    def apply_replay_postlude(self, *, operations: list[ReplayPostludeOperation]) -> None:
        """Apply operations observed after simulation but before the native tick returns."""

        for operation in operations:
            match operation:
                case PerkMenuOpenCommand():
                    perk_selection_open_choices(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                    )
                case _:
                    raise RuntimeError(f"unhandled replay postlude operation: {type(operation).__name__}")

    def step_tick(
        self,
        *,
        dt: float,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
        commands: list[GameCommand] | None = None,
        prelude_post_apply_sfx: list[SfxId] | None = None,
    ) -> DeterministicSessionTick:
        timing = self.timing_for_dt(dt)
        mode_runtime = self.mode_runtime
        mode_runtime.before_step()

        post_apply_sfx = list(prelude_post_apply_sfx or ())
        for cmd in commands or ():
            match cmd:
                case PerkPickCommand(choice_index=ci):
                    picked = perk_selection_pick(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        ci,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                        dt=timing.dt_sim,
                        creatures=self.world.creatures.entries,
                        refresh_choices=False,
                    )
                    if picked is not None:
                        post_apply_sfx.append(SfxId.UI_BONUS)
                case PerkMenuOpenCommand():
                    perk_selection_open_choices(
                        self.world.state,
                        self.world.players,
                        self.world.state.perk_selection,
                        game_mode=self.game_mode,
                        player_count=len(self.world.players),
                    )
                case TypoCharCommand() | TypoBackspaceCommand() | TypoSubmitCommand():
                    if self.game_mode != GameMode.TYPO:
                        raise RuntimeError(f"Typ-o command in non-Typo session: {type(cmd).__name__}")
                    apply_typo_command(self.world, cmd)
                case _:
                    raise RuntimeError(f"unhandled command type: {type(cmd).__name__}")

        tick_inputs = inputs
        if tick_inputs is not None:
            tick_inputs = mode_runtime.transform_inputs(tick_inputs)

        state = self.world.state
        dt_sim_ms = float(timing.dt_sim_ms_i32)
        dt_raw_ms = float(timing.dt_ms_i32)
        elapsed_before_ms = self.elapsed_ms

        mid_step_runtime = None
        if mode_runtime.needs_mid_step():
            ctx = MidStepContext(
                world=self.world,
                elapsed_before_ms=elapsed_before_ms,
                dt_sim_ms=dt_sim_ms,
                dt_raw_ms=dt_raw_ms,
                world_size=self.world_size,
            )
            mid_step_runtime = _SessionWorldMidStepRuntime(
                mode_runtime=mode_runtime,
                ctx=ctx,
            )

        fx_queue = self.terrain_fx.decals
        fx_queue_rotated = self.terrain_fx.corpses
        presentation_rng: CrandLike
        recording_rng: RecordingCrand | None = None
        if trace_rng:
            recording_rng = RecordingCrand(state.rng)
            presentation_rng = recording_rng
        else:
            presentation_rng = state.rng

        normalized_inputs = normalize_input_frame(tick_inputs, player_count=len(self.world.players)).as_list()
        state.game_mode = self.game_mode
        state.demo_mode_active = self.demo_mode_active

        prev_audio = [
            (player.shot_seq, player.weapon.reload_active, player.weapon.reload_timer) for player in self.world.players
        ]
        prev_perk_pending = state.perk_selection.pending_count

        events = self.world.step(
            timing.dt_sim,
            # Session timing already applied the outer-loop perk transforms so
            # mode hooks and the world share the same native frame delta.
            apply_world_dt_steps=False,
            defer_camera_shake_update=self.defer_camera_shake_update,
            defer_freeze_corpse_fx=False,
            mid_step_runtime=mid_step_runtime,
            inputs=normalized_inputs,
            world_size=self.world_size,
            damage_scale_by_type=self.damage_scale_by_type,
            detail_preset=self.detail_preset,
            violence_disabled=self.violence_disabled,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            game_mode=self.game_mode,
            perk_progression_enabled=self.perk_progression_enabled,
            game_tune_started=self.game_tune_started,
        )

        presentation_trace = PresentationRngTrace()
        plan_ns_start = time.perf_counter_ns()
        presentation = plan_world_presentation_step(
            state=state,
            players=self.world.players,
            fx_queue=fx_queue,
            hits=events.hits,
            pickups=events.pickups,
            event_sfx=events.sfx,
            prev_audio=prev_audio,
            prev_perk_pending=prev_perk_pending,
            game_mode=self.game_mode,
            demo_mode_active=self.demo_mode_active,
            perk_progression_enabled=self.perk_progression_enabled,
            rng=presentation_rng,
            detail_preset=self.detail_preset,
            violence_disabled=self.violence_disabled,
            game_tune_started=self.game_tune_started,
            trigger_game_tune=events.trigger_game_tune,
            hit_sfx=events.hit_sfx,
        )
        presentation_plan_ms = (time.perf_counter_ns() - plan_ns_start) / 1_000_000.0
        if recording_rng is not None:
            presentation_trace.draws_total = int(recording_rng.calls)

        presentation = msgspec.structs.replace(
            presentation,
            terrain_fx=self.terrain_fx.take_batch(),
            post_apply_sfx=tuple(post_apply_sfx),
        )
        step = DeterministicStepResult(
            dt_sim=timing.dt_sim,
            timing=timing,
            events=events,
            presentation=presentation,
            presentation_rng_trace=presentation_trace,
        )
        if step.presentation.trigger_game_tune:
            self.game_tune_started = True

        mode_runtime.post_step(
            PostStepContext(
                world=self.world,
                step_result=step,
                dt_sim_ms=dt_sim_ms,
                world_size=self.world_size,
                detail_preset=self.detail_preset,
            ),
        )

        creature_count_world_step = sum(1 for c in self.world.creatures.entries if c.active)

        if self.finalize_post_render_lifecycle:
            self.world.creatures.finalize_post_render_lifecycle()

        dt_elapsed = dt_raw_ms if self.elapsed_uses_raw_dt else dt_sim_ms
        self.elapsed_ms = elapsed_before_ms + dt_elapsed

        return DeterministicSessionTick(
            step=step,
            elapsed_ms=self.elapsed_ms,
            creature_count_world_step=creature_count_world_step,
            presentation_plan_ms=float(presentation_plan_ms),
        )
