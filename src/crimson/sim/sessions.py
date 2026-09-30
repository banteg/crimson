from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..camera import camera_update_for_players
from ..game_modes import GameMode
from ..perks.availability import prepare_perk_availability
from ..perks.selection import (
    perk_selection_pick,
)
from ..rng_caller_static import RngCallerStatic
from ..tutorial.runtime import tutorial_input_transform
from ..typo.runtime import TYPO_TIME_SCALE_FACTOR, TypoCommand, typo_gameplay_update
from ..weapon_runtime.availability import prepare_weapon_availability
from .commands import (
    GameCommand,
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from .input import PlayerInput
from .mode_updates import ModeState, QuestSpawnState
from .presentation_step import DeterministicPresentationPlan
from .run_result import RunOutcome, all_players_dead, death_transition_ready
from .terrain_fx import TerrainFxScratch
from .timing import FrameTiming, reflex_boost_time_scale_factor
from .world_state import WorldEvents, WorldState

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
    # Native called `game_save_status` during this tick; the live mode writes the status file.
    save_status: bool = False
    # Set on the tick that ends the run; a valid replay ends on this tick.
    outcome: RunOutcome | None = None


class IllegalCommandError(ValueError):
    """A command the live UI could not have issued in the current state."""


# ---------------------------------------------------------------------------
# Mode runtime system
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Shared timing helper
# ---------------------------------------------------------------------------


def _session_timing(world: WorldState, dt: float) -> FrameTiming:
    """Compute frame timing from world state. Used by all session types."""
    state = world.state
    if state.game_mode == GameMode.TYPO:
        # `game_frame_update` applies Reflex Boosted only in `GAME_STATE_GAMEPLAY`.
        return FrameTiming.compute(
            dt, time_scale_active_entry=bool(state.time_scale_active), time_scale_factor=TYPO_TIME_SCALE_FACTOR,
        )
    world_dt = world.world_dt_after_perk_steps(dt)
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

    perk_progression_enabled: bool

    # Mutable timing
    elapsed_ms: float = 0.0
    terrain_fx: TerrainFxScratch = msgspec.field(default_factory=TerrainFxScratch)

    mode_state: ModeState = None

    def __post_init__(self) -> None:
        state = self.world.state
        prepare_weapon_availability(state)
        prepare_perk_availability(state)

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _session_timing(self.world, dt)

    @property
    def run_elapsed_ms(self) -> float:
        """Elapsed run time as scored: the spawn timeline for quests, session time otherwise."""

        if isinstance(self.mode_state, QuestSpawnState):
            return float(self.mode_state.spawn_timeline_ms)
        return float(self.elapsed_ms)

    def terminal_outcome(self) -> RunOutcome | None:
        """Outcome when this tick ends the run in live play, else None."""

        players = self.world.players
        match self.world.state.game_mode:
            case GameMode.SURVIVAL:
                return RunOutcome.DEATH if death_transition_ready(players) else None
            case GameMode.QUESTS:
                # `gameplay_update_and_render` checks for death after `quest_mode_update`, so a
                # death replaces pending quest results.
                if death_transition_ready(players):
                    return RunOutcome.DEATH
                if isinstance(self.mode_state, QuestSpawnState) and self.mode_state.completed:
                    return RunOutcome.QUEST_COMPLETED
                return None
            case GameMode.RUSH:
                # No death-animation hold: Rush stops simulating on death.
                return RunOutcome.DEATH if all_players_dead(players) else None
            case GameMode.TYPO:
                # `typo_gameplay_update_and_render` plays the death animation out, like Survival.
                return RunOutcome.DEATH if death_transition_ready(players) else None
            case _:
                return None

    def end_outcome(self) -> RunOutcome:
        """Outcome of a run whose recording stops after the current tick."""

        match self.world.state.game_mode:
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

    def _mode_inputs(self, inputs: Sequence[PlayerInput]) -> Sequence[PlayerInput]:
        match self.world.state.game_mode:
            case GameMode.TUTORIAL:
                return tutorial_input_transform(self.world, inputs)
            case _:
                return inputs

    def _require_perk_command_allowed(self, name: str) -> None:
        # The perk prompt only offers the menu while a perk is pending and a
        # player is alive; each command is checked against the state left by
        # the commands before it.
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
                    game_mode=self.world.state.game_mode,
                    dt=timing.dt_sim,
                    creatures=self.world.creatures.entries,
                )
                if picked is None:
                    raise IllegalCommandError(f"perk_pick choice_index={int(choice_index)} is not an offered choice")
                return SfxId.UI_BONUS
            case _:
                raise RuntimeError(f"unhandled command type: {type(command).__name__}")
        return None

    def step_tick(
        self,
        *,
        dt: float,
        inputs: Sequence[PlayerInput],
        commands: Sequence[GameCommand] | None = None,
    ) -> DeterministicSessionTick:
        post_apply_sfx: list[SfxId] = []
        typo_commands: list[TypoCommand] = []
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
                case TypoCharCommand() | TypoBackspaceCommand() | TypoSubmitCommand():
                    if self.world.state.game_mode != GameMode.TYPO:
                        raise IllegalCommandError(f"Typ-o command in non-Typo session: {type(command).__name__}")
                    typo_commands.append(command)
                case _:
                    raise RuntimeError(f"unhandled command type: {type(command).__name__}")

        # Picks belong to the between-tick prelude (the perk screen pauses the
        # game). A menu request opens mid-tick at the native point, see
        # `WorldState.step`. Typ-o input belongs inside the tick, at the start of
        # `typo_gameplay_update_and_render`.
        timing = self.timing_for_dt(dt)
        state = self.world.state
        dt_sim_ms = float(timing.dt_sim_ms_i32)
        elapsed_before_ms = self.elapsed_ms

        fx_queue = self.terrain_fx.decals
        fx_queue_rotated = self.terrain_fx.corpses
        if state.game_mode == GameMode.TYPO:
            events = typo_gameplay_update(
                self.world,
                commands=typo_commands,
                timing=timing,
                fx_queue=fx_queue,
                fx_queue_rotated=fx_queue_rotated,
                elapsed_ms=elapsed_before_ms,
            )
        else:
            events = self.world.step(
                timing.dt_sim,
                inputs=self._mode_inputs(inputs),
                fx_queue=fx_queue,
                fx_queue_rotated=fx_queue_rotated,
                perk_progression_enabled=self.perk_progression_enabled,
                mode_state=self.mode_state,
                elapsed_ms=elapsed_before_ms,
                open_perk_menu=open_perk_menu,
            )

        quest_spawn = self.mode_state if isinstance(self.mode_state, QuestSpawnState) else None
        if quest_spawn is not None and quest_spawn.play_hit_sfx:
            post_apply_sfx.append(SfxId.QUESTHIT)
        presentation = DeterministicPresentationPlan(
            trigger_game_tune=events.trigger_game_tune,
            sfx=(*events.hit_sfx, *events.sfx),
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
        self.elapsed_ms = elapsed_before_ms + dt_sim_ms

        step.elapsed_ms = self.elapsed_ms
        step.creature_count_world_step = events.creature_count_before_render
        # `quest_mode_update` saves the status on each frame of its `timer > 2500` branch.
        step.save_status = quest_spawn is not None and quest_spawn.completed
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
