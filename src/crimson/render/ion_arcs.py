"""Shared presentation geometry for Ion impact arcs and their RTX sources."""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from ..creatures.lifecycle import creature_lifecycle_is_collidable
from ..perks import PerkId
from ..projectiles.types import Projectile, ProjectileTemplateId
from .beam_profiles import STREAK_SCALES

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureState
    from .frame import RenderFrame

ION_TYPES = frozenset((ProjectileTemplateId.ION_RIFLE, ProjectileTemplateId.ION_MINIGUN, ProjectileTemplateId.ION_CANNON))


def ion_arc_targets(frame: RenderFrame, projectile: Projectile) -> Iterator[CreatureState]:
    """Match the visible impact pass, including native slot-zero exclusion."""
    if not projectile.active or projectile.type_id not in ION_TYPES or not 0.0 < projectile.life_timer < 0.4:
        return
    scale = STREAK_SCALES[projectile.type_id]
    reach = scale * (1.2 if PerkId.ION_GUN_MASTER in frame.state.perks else 1.0) * 40.0
    for creature in frame.creatures.entries[1:]:
        if not creature.active or not creature_lifecycle_is_collidable(creature.death_timer):
            continue
        if projectile.pos.distance_to(creature.pos) - reach >= float(creature.size) * 0.14285715 + 3.0:
            continue
        yield creature
