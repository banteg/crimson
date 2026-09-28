from __future__ import annotations

from ..game_modes import GameMode
from ..quests.level import QuestLevel
from ..quests.types import SpawnEntry
from ..sim.world_state import WorldState
from ..tutorial import reset_tutorial_state
from ..typo.state import reset_typo_state
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from .mode_updates import QuestSpawnState, RushSpawnState, SurvivalSpawnState
from .sessions import DeterministicSession


def build_survival_session(
    *,
    world: WorldState,
    apply_world_dt_steps: bool = True,
) -> tuple[DeterministicSession, SurvivalSpawnState]:
    world.state.game_mode = GameMode.SURVIVAL
    spawn = SurvivalSpawnState()
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=True,
        apply_world_dt_steps=apply_world_dt_steps,
        mode_state=spawn,
    )
    return session, spawn


def build_rush_session(
    *,
    world: WorldState,
) -> tuple[DeterministicSession, RushSpawnState]:
    world.state.game_mode = GameMode.RUSH
    spawn = RushSpawnState()
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=False,
        mode_state=spawn,
    )
    return session, spawn


def build_quest_session(
    *,
    world: WorldState,
    apply_world_dt_steps: bool,
    spawn_entries: tuple[SpawnEntry, ...],
    quest_level: QuestLevel | None,
    start_weapon_id: WeaponId | None,
) -> tuple[DeterministicSession, QuestSpawnState]:
    world.state.game_mode = GameMode.QUESTS
    world.state.quest_level = quest_level

    weapon_id = WeaponId.PISTOL if start_weapon_id in (None, WeaponId.NONE) else start_weapon_id
    for player in world.players:
        weapon_assign_player(player, weapon_id, state=world.state)

    quest_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=True,
        apply_world_dt_steps=apply_world_dt_steps,
        mode_state=quest_state,
    )
    return session, quest_state


def build_typo_session(
    *,
    world: WorldState,
    dictionary_words: tuple[str, ...] = (),
    highscore_names: tuple[str, ...] = (),
) -> DeterministicSession:
    world.state.game_mode = GameMode.TYPO
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
        dictionary_words=dictionary_words,
        highscore_names=highscore_names,
    )
    return DeterministicSession(
        world=world,
        perk_progression_enabled=False,
    )


def build_tutorial_session(
    *,
    world: WorldState,
) -> DeterministicSession:
    world.state.game_mode = GameMode.TUTORIAL
    weapon_assign_player(world.players[0], WeaponId.PISTOL, state=world.state)
    reset_tutorial_state(
        world.state.tutorial,
        world.state.tutorial_overlay,
    )
    return DeterministicSession(
        world=world,
        perk_progression_enabled=True,
    )
