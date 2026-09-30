from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.perks.availability import prepare_perk_availability
from crimson.quests.level import QuestLevel
from crimson.sim.sessions import DeterministicSession
from crimson.sim.world_reset import build_reset_world
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import prepare_weapon_availability


def make_world(
    *,
    seed: int = 0xBEEF,
    player_count: int = 1,
    preserve_bugs: bool = False,
    quest_level: QuestLevel | None = None,
) -> WorldState:
    world = build_reset_world(
        seed=seed, player_count=player_count, preserve_bugs=preserve_bugs,
    )
    world.state.quest_level = quest_level
    # A session prepares both tables on start; so do sessionless test worlds.
    prepare_weapon_availability(world.state)
    prepare_perk_availability(world.state)
    return world


def make_session(
    *,
    seed: int = 0xBEEF,
    player_count: int = 1,
    game_mode: GameMode = GameMode.SURVIVAL,
    perk_progression_enabled: bool = True,
) -> tuple[DeterministicSession, WorldState]:
    world = make_world(seed=seed, player_count=player_count)
    world.state.game_mode = game_mode
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=perk_progression_enabled,
    )
    return session, world
