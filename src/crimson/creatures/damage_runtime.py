from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ..owner_ref import OwnerRef

if TYPE_CHECKING:
    from .runtime import CreatureState


class CreatureDamageRuntime(msgspec.Struct):
    def apply_creature_damage(
        self,
        creature_index: int,
        damage: float,
        damage_type: int,
        impulse: Vec2,
        owner: OwnerRef,
    ) -> None:
        _ = creature_index, damage, damage_type, impulse, owner

    def kill_creature_no_corpse(self, creature_index: int, owner: OwnerRef) -> None:
        _ = creature_index, owner

    def on_secondary_detonation_kill(self, creature_index: int) -> None:
        _ = creature_index

    def on_creature_lethal(
        self,
        creature_index: int,
        resolve_death_sfx: Callable[[], tuple[SfxId, ...]],
    ) -> None:
        # Native `creature_apply_damage` runs `creature_handle_death` first and only
        # then draws the death-SFX / shock-burst rands; implementations must invoke
        # `resolve_death_sfx` after death handling to keep the RNG stream aligned.
        _ = creature_index, resolve_death_sfx


class DirectCreatureDamageRuntime(CreatureDamageRuntime):
    creatures: Sequence[CreatureState] = ()

    def apply_creature_damage(
        self,
        creature_index: int,
        damage: float,
        damage_type: int,
        impulse: Vec2,
        owner: OwnerRef,
    ) -> None:
        _ = damage_type, impulse, owner
        if damage <= 0.0:
            return
        idx = int(creature_index)
        if not (0 <= idx < len(self.creatures)):
            return
        self.creatures[idx].hp -= float(damage)

    def kill_creature_no_corpse(self, creature_index: int, owner: OwnerRef) -> None:
        _ = owner
        idx = int(creature_index)
        if not (0 <= idx < len(self.creatures)):
            return
        creature = self.creatures[idx]
        creature.hp = -1.0
        creature.active = False
