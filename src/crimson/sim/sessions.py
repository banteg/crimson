from __future__ import annotations

from collections.abc import Sequence
from functools import partial

import msgspec

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..camera import camera_update_for_players
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
from ..tutorial.runtime import tutorial_input_transform, tutorial_post_step
from ..typo.runtime import apply_typo_command, typo_before_step, typo_input_transform, typo_mid_step, typo_post_step
from ..weapon_runtime.availability import prepare_weapon_availability
from ..weapons import WeaponId
from .commands import (
    GameCommand,
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from .input import PlayerInput
from .presentation_step import DeterministicPresentationPlan, plan_world_presentation_step
from .run_result import RunOutcome, all_players_dead, death_transition_ready
from .terrain_fx import TerrainFxScratch
from .timing import FrameTiming, reflex_boost_time_scale_factor
from .world_state import WorldEvents, WorldState

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE
RUSH_FORCED_AMMO = 30.0

# ---------------------------------------------------------------------------
# Tick result types
# ---------------------------------------------------------------------------


class DeterministicSessionTick(msgspec.Struct):
    dt_sim: float
    timing: FrameTiming
    events: WorldEvents
    presentation: DeterministicPresentationPlan
    elapsed_ms: float = 0.0
    creature_count_world_step: int = 0
    quest_completed: bool = False
    # Set on the tick that ends the run; a valid replay ends on this tick.
    outcome: RunOutcome | None = None


class IllegalCommandError(ValueError):
    """A command the live UI could not have issued in the current state."""


# ---------------------------------------------------------------------------
# Mode runtime system
# ---------------------------------------------------------------------------


class MidStepContext(msgspec.Struct, frozen=True):
    """Context passed to mid-step spawn hooks during deterministic stepping."""

    world: WorldState
    elapsed_before_ms: float
    dt_sim_ms: float
    dt_raw_ms: float
    detail_preset: int


class PostStepContext(msgspec.Struct, frozen=True):
    """Context passed to post-step hooks during deterministic stepping."""

    world: WorldState
    dt_sim_ms: float
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


def survival_mid_step(ctx: MidStepContext, spawn: SurvivalSpawnState) -> None:
    state = ctx.world.state
    survival_update_weapon_handouts(
        state,
        ctx.world.players,
        survival_elapsed_ms=ctx.elapsed_before_ms,
    )

    player_level = ctx.world.players[0].level
    stage, milestone_calls = advance_survival_spawn_stage(spawn.stage, player_level=int(player_level))
    spawn.stage = stage
    for call in milestone_calls:
        ctx.world.creatures.spawn_template(
            call.template_id,
            call.pos,
            float(call.heading),
            state=state,
            detail_preset=ctx.detail_preset,
        )

    player_xp = ctx.world.players[0].experience
    cooldown, wave_spawns = tick_survival_wave_spawns(
        spawn.spawn_cooldown_ms,
        ctx.dt_sim_ms,
        state.rng,
        player_count=len(ctx.world.players),
        survival_elapsed_ms=ctx.elapsed_before_ms,
        player_experience=int(player_xp),
    )
    spawn.spawn_cooldown_ms = cooldown
    ctx.world.creatures.spawn_inits(wave_spawns)


def rush_mid_step(ctx: MidStepContext, spawn: RushSpawnState) -> None:
    state = ctx.world.state
    # Native `rush_mode_update` stomps the weapon id and ammo every frame, after
    # the player update and without `weapon_assign_player`: the run starts on the
    # reset pistol (its clip and 0.8 s cooldown), and a manual reload still runs.
    for player in ctx.world.players:
        player.weapon.weapon_id = RUSH_WEAPON_ID
        player.weapon.ammo = RUSH_FORCED_AMMO
    cooldown, spawns = tick_rush_mode_spawns(
        spawn.spawn_cooldown_ms,
        ctx.dt_raw_ms,
        state.rng,
        player_count=len(ctx.world.players),
        survival_elapsed_ms=int(ctx.elapsed_before_ms),
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
        creatures_none_active=creatures_none_active,
        no_creatures_timer_ms=spawn.no_creatures_timer_ms,
    )
    spawn.spawn_entries = entries
    spawn.spawn_timeline_ms = float(timeline_ms)
    spawn.no_creatures_timer_ms = float(no_creatures_timer_ms)
    spawn_table_empty_now = quest_spawn_table_empty(spawn.spawn_entries)

    if creatures_none_active and spawn_table_empty_now:
        state.bonuses.reflex_boost = 0.0
        state.time_scale_active = False

    for call in spawns:
        ctx.world.creatures.spawn_template(
            call.template_id,
            call.pos,
            float(call.heading),
            state=state,
            detail_preset=ctx.detail_preset,
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


# Per-mode spawn state. Typ-o and tutorial keep theirs in the gameplay state.
type ModeState = SurvivalSpawnState | RushSpawnState | QuestSpawnState | None


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
    )


# ---------------------------------------------------------------------------
# Unified deterministic session (replaces Survival/Rush/Tutorial/Typo/WorldTick)
# ---------------------------------------------------------------------------


class DeterministicSession(msgspec.Struct):
    # Core state
    world: WorldState

    # Mode identity
    game_mode: GameMode
    perk_progression_enabled: bool

    # Sim config
    detail_preset: int = 5
    violence_disabled: int = 0
    game_tune_started: bool = False
    apply_world_dt_steps: bool = True
    elapsed_uses_raw_dt: bool = False
    # Reject perk commands the live UI cannot issue (they would otherwise no-op
    # or reroll perk choices). Original-capture playback replays native menu
    # activity verbatim and disables this.
    strict_commands: bool = True

    # Mutable timing
    elapsed_ms: float = 0.0
    terrain_fx: TerrainFxScratch = msgspec.field(default_factory=TerrainFxScratch)

    mode_state: ModeState = None

    def __post_init__(self) -> None:
        state = self.world.state
        state.game_mode = self.game_mode
        prepare_weapon_availability(state)
        prepare_perk_availability(state)

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _session_timing(
            self.world,
            dt,
            apply_world_dt_steps=bool(self.apply_world_dt_steps),
        )

    @property
    def run_elapsed_ms(self) -> float:
        """Elapsed run time as scored: the spawn timeline for quests, session time otherwise."""

        if isinstance(self.mode_state, QuestSpawnState):
            return float(self.mode_state.spawn_timeline_ms)
        return float(self.elapsed_ms)

    def terminal_outcome(self) -> RunOutcome | None:
        """Outcome when this tick ends the run in live play, else None."""

        players = self.world.players
        match self.game_mode:
            case GameMode.SURVIVAL:
                return RunOutcome.DEATH if death_transition_ready(players) else None
            case GameMode.QUESTS:
                if isinstance(self.mode_state, QuestSpawnState) and self.mode_state.completed:
                    return RunOutcome.QUEST_COMPLETED
                return RunOutcome.DEATH if death_transition_ready(players) else None
            case GameMode.RUSH | GameMode.TYPO:
                # No death-animation hold: Rush and Typ-o stop simulating on death.
                return RunOutcome.DEATH if all_players_dead(players) else None
            case _:
                return None

    def end_outcome(self) -> RunOutcome:
        """Outcome of a run whose recording stops after the current tick."""

        match self.game_mode:
            case GameMode.QUESTS:
                # The failed-quest countdown keeps running while paused, so a
                # failed run may close between ticks before the death animation ends.
                outcome = self.terminal_outcome()
                if outcome is not None:
                    return outcome
                return RunOutcome.DEATH if all_players_dead(self.world.players) else RunOutcome.INCOMPLETE
            case GameMode.TUTORIAL:
                # The tutorial has no terminal tick: players leave it from the UI.
                stage_index = int(self.world.state.tutorial.stage_index)
                return RunOutcome.TUTORIAL_COMPLETED if stage_index >= 8 else RunOutcome.INCOMPLETE
            case _:
                return self.terminal_outcome() or RunOutcome.INCOMPLETE

    def _mode_before_step(self) -> None:
        match self.game_mode:
            case GameMode.TYPO:
                typo_before_step(self.world)

    def _mode_inputs(self, inputs: Sequence[PlayerInput]) -> Sequence[PlayerInput]:
        match self.game_mode:
            case GameMode.TYPO:
                return typo_input_transform(self.world, inputs)
            case GameMode.TUTORIAL:
                return tutorial_input_transform(self.world, inputs)
            case _:
                return inputs

    def _mode_update(self, ctx: MidStepContext) -> None:
        """The mode's native update, run inside the world step after player updates."""

        match self.mode_state:
            case SurvivalSpawnState():
                survival_mid_step(ctx, self.mode_state)
            case RushSpawnState():
                rush_mid_step(ctx, self.mode_state)
            case QuestSpawnState():
                quest_mid_step(ctx, self.mode_state)
            case None if self.game_mode == GameMode.TYPO:
                typo_mid_step(ctx)

    def _mode_after_step(self, ctx: PostStepContext) -> None:
        match self.game_mode:
            case GameMode.TYPO:
                typo_post_step(ctx)
            case GameMode.TUTORIAL:
                tutorial_post_step(ctx)

    def _require_perk_command_allowed(self, name: str) -> None:
        # The perk prompt only offers the menu while a perk is pending and a
        # player is alive; each command is checked against the state left by
        # the commands before it.
        if not self.strict_commands:
            return
        if int(self.world.state.perk_selection.pending_count) <= 0:
            raise IllegalCommandError(f"{name} without a pending perk")
        if all_players_dead(self.world.players):
            raise IllegalCommandError(f"{name} while every player is dead")

    def apply_command(self, command: GameCommand, *, dt: float) -> SfxId | None:
        match command:
            case PerkPickCommand(choice_index=choice_index):
                self._require_perk_command_allowed("perk_pick")
                # Each pick sees any timing changes made by earlier picks.
                timing = self.timing_for_dt(dt)
                picked = perk_selection_pick(
                    self.world.state,
                    self.world.players,
                    choice_index,
                    game_mode=self.game_mode,
                    dt=timing.dt_sim,
                    creatures=self.world.creatures.entries,
                )
                if picked is None and self.strict_commands:
                    raise IllegalCommandError(f"perk_pick choice_index={int(choice_index)} is not an offered choice")
                return SfxId.UI_BONUS if picked is not None else None
            case PerkMenuOpenCommand():
                # Between ticks only in original captures; recorded runs open mid-tick.
                self._require_perk_command_allowed("perk_menu_open")
                perk_selection_open_choices(self.world.state, self.world.players, game_mode=self.game_mode)
            case TypoCharCommand() | TypoBackspaceCommand() | TypoSubmitCommand():
                if self.game_mode != GameMode.TYPO:
                    raise IllegalCommandError(f"Typ-o command in non-Typo session: {type(command).__name__}")
                apply_typo_command(self.world, command)
            case _:
                raise RuntimeError(f"unhandled command type: {type(command).__name__}")
        return None

    def step_tick(
        self,
        *,
        dt: float,
        inputs: Sequence[PlayerInput] | None,
        commands: Sequence[GameCommand] | None = None,
        prelude_post_apply_sfx: list[SfxId] | None = None,
    ) -> DeterministicSessionTick:
        post_apply_sfx = list(prelude_post_apply_sfx or ())
        tick_commands: list[GameCommand] = []
        open_perk_menu = False
        for command in commands or ():
            match command:
                case PerkPickCommand():
                    sfx = self.apply_command(command, dt=dt)
                    if sfx is not None:
                        post_apply_sfx.append(sfx)
                case PerkMenuOpenCommand():
                    # Live play requests the menu only while it may open.
                    self._require_perk_command_allowed("perk_menu_open")
                    open_perk_menu = True
                case _:
                    tick_commands.append(command)

        # Picks belong to the between-tick prelude (the perk screen pauses the
        # game). A menu request opens mid-tick at the native point, see
        # `WorldState.step`. Typ-o input belongs inside the tick, after its
        # loadout enforcement (and reload sound).
        timing = self.timing_for_dt(dt)
        self._mode_before_step()
        for command in tick_commands:
            self.apply_command(command, dt=dt)

        tick_inputs = inputs
        if tick_inputs is not None:
            tick_inputs = self._mode_inputs(tick_inputs)

        state = self.world.state
        dt_sim_ms = float(timing.dt_sim_ms_i32)
        dt_raw_ms = float(timing.dt_ms_i32)
        elapsed_before_ms = self.elapsed_ms

        mode_update = None
        if self.mode_state is not None or self.game_mode == GameMode.TYPO:
            ctx = MidStepContext(
                world=self.world,
                elapsed_before_ms=elapsed_before_ms,
                dt_sim_ms=dt_sim_ms,
                dt_raw_ms=dt_raw_ms,
                detail_preset=self.detail_preset,
            )
            mode_update = partial(self._mode_update, ctx)

        fx_queue = self.terrain_fx.decals
        fx_queue_rotated = self.terrain_fx.corpses
        prev_audio = [
            (player.shot_seq, player.weapon.reload_active, player.weapon.reload_timer) for player in self.world.players
        ]
        prev_perk_pending = state.perk_selection.pending_count

        events = self.world.step(
            timing.dt_sim,
            mode_update=mode_update,
            inputs=tick_inputs,
            detail_preset=self.detail_preset,
            violence_disabled=self.violence_disabled,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            game_mode=self.game_mode,
            perk_progression_enabled=self.perk_progression_enabled,
            game_tune_started=self.game_tune_started,
            open_perk_menu=open_perk_menu,
        )

        presentation = plan_world_presentation_step(
            state=state,
            players=self.world.players,
            pickups=events.pickups,
            event_sfx=events.sfx,
            prev_audio=prev_audio,
            prev_perk_pending=prev_perk_pending,
            perk_progression_enabled=self.perk_progression_enabled,
            trigger_game_tune=events.trigger_game_tune,
            hit_sfx=events.hit_sfx,
        )

        quest_spawn = self.mode_state if isinstance(self.mode_state, QuestSpawnState) else None
        if quest_spawn is not None and quest_spawn.play_hit_sfx:
            post_apply_sfx.append(SfxId.QUESTHIT)
        presentation = msgspec.structs.replace(
            presentation,
            terrain_fx=self.terrain_fx.take_batch(),
            post_apply_sfx=tuple(SfxRequest(sfx) for sfx in post_apply_sfx),
            sfx_dt=timing.dt_audio,
            play_quest_completion_music=quest_spawn is not None and quest_spawn.play_completion_music,
        )
        step = DeterministicSessionTick(
            dt_sim=timing.dt_sim,
            timing=timing,
            events=events,
            presentation=presentation,
        )
        if step.presentation.trigger_game_tune:
            self.game_tune_started = True

        creature_count_world_step = sum(1 for c in self.world.creatures.entries if c.active)

        # Native culls corpses while rendering the world, before
        # `tutorial_timeline_update` reads its bonus carrier.
        self.world.creatures.finalize_post_render_lifecycle()
        self._mode_after_step(
            PostStepContext(
                world=self.world,
                dt_sim_ms=dt_sim_ms,
                detail_preset=self.detail_preset,
            ),
        )

        dt_elapsed = dt_raw_ms if self.elapsed_uses_raw_dt else dt_sim_ms
        self.elapsed_ms = elapsed_before_ms + dt_elapsed

        step.elapsed_ms = self.elapsed_ms
        step.creature_count_world_step = creature_count_world_step
        step.quest_completed = quest_spawn is not None and quest_spawn.completed
        step.outcome = self.terminal_outcome()
        step.presentation = msgspec.structs.replace(
            step.presentation,
            camera=camera_update_for_players(self.world.players, state.camera_shake_offset),
            reflex_boost_timer=float(state.bonuses.reflex_boost),
        )
        # `game_frame_update` ends every frame with a discarded draw. Frames outside
        # gameplay (pause, perk menu) draw too in native; they depend on wall-clock
        # time, so the port fixes them at zero.
        state.rng.rand_tagged(RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED)
        return step
