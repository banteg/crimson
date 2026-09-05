from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ..owner_ref import OwnerRef

# The callback must handle death synchronously, then invoke the supplied
# follow-up before returning: native impulse/SFX/shock RNG runs in that order.
type CreatureLethalHandler = Callable[[int, Callable[[], tuple[SfxId, ...]]], None]


class CreatureDamageRuntime(Protocol):
    """Required gameplay damage semantics; implementations own death handling."""

    def apply_creature_damage(
        self, creature_index: int, damage: float, damage_type: int, impulse: Vec2, owner: OwnerRef,
    ) -> None: ...
    def kill_creature_no_corpse(self, creature_index: int, owner: OwnerRef) -> None: ...
    def on_bubblegun_expiry_sfx(self, creature_index: int, sound_slot: int) -> None: ...
    def on_secondary_detonation_kill(self, creature_index: int) -> None: ...

    def on_creature_lethal(
        self, creature_index: int, resolve_damage_followup: Callable[[], tuple[SfxId, ...]],
    ) -> None: ...
