from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.sim.sessions import DeterministicSession
from crimson.sim.world_reset import build_reset_world
from crimson.sim.world_state import WorldState


def make_world(
    *,
    world_size: float = 1024.0,
    seed: int = 0xBEEF,
    player_count: int = 1,
    preserve_bugs: bool = False,
) -> WorldState:
    return build_reset_world(
        world_size=world_size, seed=seed, player_count=player_count, preserve_bugs=preserve_bugs,
    )


def make_session(
    *,
    world_size: float = 1024.0,
    seed: int = 0xBEEF,
    player_count: int = 1,
    game_mode: GameMode = GameMode.SURVIVAL,
    perk_progression_enabled: bool = True,
) -> tuple[DeterministicSession, WorldState]:
    world = make_world(world_size=world_size, seed=seed, player_count=player_count)
    session = DeterministicSession(
        world=world,
        world_size=world_size,
        game_mode=game_mode,
        perk_progression_enabled=perk_progression_enabled,
    )
    return session, world
