"""Shared presentation geometry for Ion impact arcs and their RTX sources."""

from __future__ import annotations

import math
from collections.abc import Iterator
from typing import TYPE_CHECKING

from ..creatures.lifecycle import creature_lifecycle_is_collidable
from ..math_parity import f32
from ..perks import PerkId
from ..projectiles.types import Projectile, ProjectileTemplateId
from .beam_profiles import STREAK_SCALES

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureState
    from .frame import RenderFrame

ION_TYPES = frozenset((ProjectileTemplateId.ION_RIFLE, ProjectileTemplateId.ION_MINIGUN, ProjectileTemplateId.ION_CANNON))
# Arcs into one cell overlap almost entirely, and two already whiten their core.
ARCS_PER_CELL = 2


def _reach(frame: RenderFrame, projectile: Projectile) -> float:
    scale = STREAK_SCALES[projectile.type_id]
    return scale * (1.2 if PerkId.ION_GUN_MASTER in frame.state.perks else 1.0) * 40.0


def ion_arc_targets(frame: RenderFrame, projectile: Projectile) -> Iterator[CreatureState]:
    """Match the visible impact pass, including native slot-zero exclusion."""
    if not projectile.active or projectile.type_id not in ION_TYPES or not 0.0 < projectile.life_timer < 0.4:
        return
    reach = _reach(frame, projectile)
    for creature in frame.creatures.entries[1:]:
        if not creature.active or not creature_lifecycle_is_collidable(creature.death_timer):
            continue
        if projectile.pos.distance_to(creature.pos) - reach >= float(creature.size) * 0.14285715 + 3.0:
            continue
        yield creature


def ion_arcs_drawn(frame: RenderFrame, projectile: Projectile) -> Iterator[CreatureState]:
    """The targets a shot draws arcs to, at most two to the creatures in one small cell (crimson-core/game/ion_arcs.cpp).

    A crowd piled under a Shock Chain otherwise gets thousands of arcs over the same pixels, white either way. Cells are
    three quarters of the inner strip's half-width (a quarter of the reach) across, in world units.
    """
    size = f32(f32(_reach(frame, projectile)) * f32(0.1875))
    arcs: dict[tuple[int, int], int] = {}
    for creature in ion_arc_targets(frame, projectile):
        cell = (math.floor(f32(creature.pos.x / size)), math.floor(f32(creature.pos.y / size)))
        arcs[cell] = arcs.get(cell, 0) + 1
        if arcs[cell] <= ARCS_PER_CELL:
            yield creature
