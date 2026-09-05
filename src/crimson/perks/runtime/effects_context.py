from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ...collision_math import within_native_find_radius
from ...creatures.lifecycle import creature_lifecycle_is_collidable
from ...effects import FxQueue
from ...sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState


def creature_find_in_radius(creatures: Sequence[CreatureState], *, pos: Vec2, radius: float, start_index: int) -> int:
    """Find the first active creature intersecting an aim radius.

    Port of `creature_find_in_radius` (0x004206a0).
    """

    start_index = max(0, int(start_index))
    max_index = min(len(creatures), 0x180)
    if start_index >= max_index:
        return -1

    radius = float(radius)

    for idx in range(start_index, max_index):
        creature = creatures[idx]
        if not creature.active:
            continue

        if not within_native_find_radius(
            origin=pos,
            target=creature.pos,
            radius=radius,
            target_size=float(creature.size),
        ):
            continue
        if not creature_lifecycle_is_collidable(creature.lifecycle_stage):
            continue
        return idx
    return -1


class PerksUpdateEffectsCtx(msgspec.Struct):
    state: GameplayState
    players: list[PlayerState]
    dt: float
    creatures: Sequence[CreatureState]
    fx_queue: FxQueue
    _aim_target_by_player_index: dict[int, int] = msgspec.field(default_factory=dict)

    def aim_target_for_player(self, player_index: int) -> int:
        player_index = int(player_index)
        if player_index in self._aim_target_by_player_index:
            return int(self._aim_target_by_player_index[player_index])

        target = -1
        if self.state.preserve_bugs and player_index != 0:
            self._aim_target_by_player_index[player_index] = int(target)
            return int(target)

        if not (0 <= player_index < len(self.players)):
            self._aim_target_by_player_index[player_index] = int(target)
            return int(target)

        player = self.players[player_index]
        if not self.state.preserve_bugs and float(player.health) <= 0.0:
            self._aim_target_by_player_index[player_index] = int(target)
            return int(target)

        target = creature_find_in_radius(
            self.creatures,
            pos=player.aim,
            radius=12.0,
            start_index=0,
        )
        self._aim_target_by_player_index[player_index] = int(target)
        return int(target)
