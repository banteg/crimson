from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.sim.sessions import DeterministicSession
from crimson.world.sim_world_state import SimWorldState


def make_session(
    *,
    world_size: float = 1024.0,
    seed: int = 0xBEEF,
    player_count: int = 1,
    game_mode: GameMode = GameMode.SURVIVAL,
    perk_progression_enabled: bool = True,
) -> tuple[DeterministicSession, SimWorldState]:
    sim_world = SimWorldState(world_size=world_size)
    sim_world.reset(seed=seed, player_count=player_count)
    session = DeterministicSession(
        world=sim_world.world_state,
        world_size=sim_world.world_size,
        damage_scale_by_type=sim_world.damage_scale_by_type,
        game_mode=game_mode,
        perk_progression_enabled=perk_progression_enabled,
    )
    return session, sim_world
