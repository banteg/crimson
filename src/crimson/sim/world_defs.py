from __future__ import annotations

from ..creatures.spawn import CreatureTypeId
from ..projectiles.types import ProjectileTemplateId

CREATURE_ASSET: dict[CreatureTypeId, str] = {
    CreatureTypeId.ZOMBIE: "zombie",
    CreatureTypeId.LIZARD: "lizard",
    CreatureTypeId.ALIEN: "alien",
    CreatureTypeId.SPIDER_SP1: "spider_sp1",
    CreatureTypeId.SPIDER_SP2: "spider_sp2",
    CreatureTypeId.TROOPER: "trooper",
}

KNOWN_PROJ_FRAMES: dict[int, tuple[int, int]] = {
    # Based on docs/atlas.md (projectile `type_id` values index the weapon table).
    ProjectileTemplateId.PULSE_GUN: (2, 0),
    ProjectileTemplateId.SPLITTER_GUN: (4, 3),
    ProjectileTemplateId.BLADE_GUN: (4, 6),
    ProjectileTemplateId.ION_MINIGUN: (4, 2),
    ProjectileTemplateId.ION_CANNON: (4, 2),
    ProjectileTemplateId.SHRINKIFIER: (4, 2),
    ProjectileTemplateId.FIRE_BULLETS: (4, 2),
    ProjectileTemplateId.ION_RIFLE: (4, 2),
}

PLASMA_PARTICLE_TYPES = frozenset(
    {
        ProjectileTemplateId.PLASMA_RIFLE,
        ProjectileTemplateId.PLASMA_MINIGUN,
        ProjectileTemplateId.PLASMA_CANNON,
        ProjectileTemplateId.SPIDER_PLASMA,
        ProjectileTemplateId.SHRINKIFIER,
    },
)

ION_TYPES = frozenset(
    {
        ProjectileTemplateId.ION_RIFLE,
        ProjectileTemplateId.ION_MINIGUN,
        ProjectileTemplateId.ION_CANNON,
    },
)

FIRE_BULLETS_TYPES = frozenset({ProjectileTemplateId.FIRE_BULLETS})

# "Beam" in the original renderer is really the Ion/Fire streak + chain UV family.
BEAM_TYPES = ION_TYPES | FIRE_BULLETS_TYPES
