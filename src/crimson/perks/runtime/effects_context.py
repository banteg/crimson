from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from grim.geom import Vec2

from ...effects import FxQueue
from ...sim.state_types import GameplayState, PlayerState
from ..helpers import perk_active
from ..ids import PerkId


class CreatureForPerks(Protocol):
    active: bool
    pos: Vec2
    hp: float
    hitbox_size: float
    collision_timer: float
    reward_value: float
    size: float


def creature_find_in_radius(creatures: Sequence[CreatureForPerks], *, pos: Vec2, radius: float, start_index: int) -> int:
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

        dist = (creature.pos - pos).length() - radius
        threshold = float(creature.size) * 0.14285715 + 3.0
        if threshold < dist:
            continue
        if float(creature.hitbox_size) < 5.0:
            continue
        return idx
    return -1


@dataclass(slots=True)
class PerksUpdateEffectsCtx:
    state: GameplayState
    players: list[PlayerState]
    dt: float
    creatures: Sequence[CreatureForPerks] | None
    fx_queue: FxQueue | None
    _aim_target: int | None = None
    _aim_source_player_index: int | None = None

    def aim_source_player(self) -> PlayerState | None:
        if self._aim_source_player_index is None:
            source_index = -1
            if self.players:
                if bool(self.state.preserve_bugs):
                    source_index = 0
                else:
                    for idx, player in enumerate(self.players):
                        if float(player.health) > 0.0:
                            source_index = int(idx)
                            break
            self._aim_source_player_index = int(source_index)
        source_index = int(self._aim_source_player_index)
        if source_index < 0 or source_index >= len(self.players):
            return None
        return self.players[source_index]

    def aim_target(self) -> int:
        if self._aim_target is not None:
            return int(self._aim_target)

        target = -1
        source_player = self.aim_source_player()
        if (
            source_player is not None
            and self.creatures is not None
            and (perk_active(source_player, PerkId.PYROKINETIC) or perk_active(source_player, PerkId.EVIL_EYES))
        ):
            target = creature_find_in_radius(
                self.creatures,
                pos=source_player.aim,
                radius=12.0,
                start_index=0,
            )
        self._aim_target = int(target)
        return int(target)
