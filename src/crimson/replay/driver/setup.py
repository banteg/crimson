from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.sim.world_reset import reset_world_players
from grim.geom import Vec2

from ...sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


class ReplayRunnerError(ValueError):
    pass


def reset_players(
    players: list[PlayerState],
    *,
    state: GameplayState,
    world_size: float,
    player_count: int,
    spawn_pos: Vec2 | None = None,
) -> None:
    """Reset `players` to the classic initial layout used by runtime reset."""

    reset_world_players(
        players,
        state=state,
        world_size=float(world_size),
        player_count=int(player_count),
        spawn_pos=spawn_pos,
    )
