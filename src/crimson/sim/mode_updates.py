"""The mode updates `gameplay_update_and_render` runs after the player updates."""

from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from ..creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from ..gameplay import survival_update_weapon_handouts
from ..math_parity import f32
from ..quests.runtime import tick_quest_completion_transition
from ..quests.timeline import quest_spawn_table_empty, quest_spawn_timeline_update
from ..quests.types import SpawnEntry
from ..weapons import WeaponId

if TYPE_CHECKING:
    from .world_state import WorldState

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE
RUSH_FORCED_AMMO = 30.0


class SurvivalSpawnState(msgspec.Struct):
    stage: int = 0
    spawn_cooldown_ms: float = 0.0


class RushSpawnState(msgspec.Struct):
    spawn_cooldown_ms: float = 0.0


class QuestSpawnState(msgspec.Struct):
    spawn_entries: tuple[SpawnEntry, ...] = ()
    # Native `quest_spawn_total_creatures`, summed once at quest start.
    total_creatures: int = 0
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0
    completed: bool = False
    play_hit_sfx: bool = False
    play_completion_music: bool = False


def survival_update(world: WorldState, spawn: SurvivalSpawnState, *, elapsed_ms: float, dt_ms: float) -> None:
    """Port of `survival_update`: weapon handouts, milestone spawns, then the wave spawner."""

    state = world.state
    survival_update_weapon_handouts(
        state,
        world.players,
        survival_elapsed_ms=elapsed_ms,
    )

    player_level = world.players[0].level
    stage, milestone_calls = advance_survival_spawn_stage(spawn.stage, player_level=int(player_level))
    spawn.stage = stage
    for call in milestone_calls:
        world.creatures.spawn_template(
            call.template_id,
            call.pos,
            float(call.heading),
            state=state,
            detail_preset=state.detail_preset,
        )

    player_xp = world.players[0].experience
    spawn.spawn_cooldown_ms = tick_survival_wave_spawns(
        world.creatures,
        spawn.spawn_cooldown_ms,
        dt_ms,
        state.rng,
        player_count=len(world.players),
        survival_elapsed_ms=elapsed_ms,
        player_experience=int(player_xp),
    )


def rush_mode_update(world: WorldState, spawn: RushSpawnState, *, elapsed_ms: float, dt_ms: float) -> None:
    state = world.state
    # Native `rush_mode_update` stomps the weapon id and ammo every frame, after
    # the player update and without `weapon_assign_player`: the run starts on the
    # reset pistol (its clip and 0.8 s cooldown), and a manual reload still runs.
    for player in world.players:
        player.weapon.weapon_id = RUSH_WEAPON_ID
        player.weapon.ammo = RUSH_FORCED_AMMO
    spawn.spawn_cooldown_ms = tick_rush_mode_spawns(
        world.creatures,
        spawn.spawn_cooldown_ms,
        dt_ms,
        state.rng,
        player_count=len(world.players),
        survival_elapsed_ms=int(elapsed_ms),
    )


def quest_mode_update(world: WorldState, spawn: QuestSpawnState, *, dt_ms: float) -> None:
    # Native runs quest_mode_update with the other mode updates before render,
    # so quest spawns draw RNG ahead of the presentation pass, like the other
    # modes' mid-steps. The scaled dt keeps the timeline (the quest score), the
    # stall timer, and the completion transition slowed under Reflex Boost.
    state = world.state
    if any(c.active for c in world.creatures.entries) or not quest_spawn_table_empty(spawn.spawn_entries):
        spawn.spawn_timeline_ms = f32(f32(spawn.spawn_timeline_ms) + f32(dt_ms))
    quest_spawn_timeline_update(world, spawn, dt_ms=dt_ms)

    creatures_none_active = not any(c.active for c in world.creatures.entries)
    spawn_table_empty_now = quest_spawn_table_empty(spawn.spawn_entries)
    if creatures_none_active and spawn_table_empty_now:
        state.bonuses.reflex_boost = 0.0
        state.time_scale_active = False

    # Native quest_mode_update has no player-alive gate on the completion
    # transition: if the timer crosses 2500 ms while the death animation is
    # still playing, the quest completes despite the player dying.
    completion_ms, completed, play_hit_sfx, play_completion_music = tick_quest_completion_transition(
        spawn.completion_transition_ms,
        frame_dt_ms=float(dt_ms),
        creatures_none_active=creatures_none_active,
        spawn_table_empty=spawn_table_empty_now,
    )
    spawn.completion_transition_ms = float(completion_ms)
    spawn.completed = bool(completed)
    spawn.play_hit_sfx = bool(play_hit_sfx)
    spawn.play_completion_music = bool(play_completion_music)


# Per-mode spawn state. Typ-o and tutorial keep theirs in the gameplay state.
type ModeState = SurvivalSpawnState | RushSpawnState | QuestSpawnState | None
