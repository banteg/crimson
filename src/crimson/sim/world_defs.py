from __future__ import annotations

from dataclasses import dataclass

from ..creatures.spawn import CreatureTypeId
from ..projectiles import ProjectileTypeId


@dataclass(frozen=True, slots=True)
class CreatureAnimInfo:
    base: int
    anim_rate: float
    mirror: bool


CREATURE_ANIM: dict[CreatureTypeId, CreatureAnimInfo] = {
    CreatureTypeId.ZOMBIE: CreatureAnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: CreatureAnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: CreatureAnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: CreatureAnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}

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
    ProjectileTypeId.PULSE_GUN: (2, 0),
    ProjectileTypeId.SPLITTER_GUN: (4, 3),
    ProjectileTypeId.BLADE_GUN: (4, 6),
    ProjectileTypeId.ION_MINIGUN: (4, 2),
    ProjectileTypeId.ION_CANNON: (4, 2),
    ProjectileTypeId.SHRINKIFIER: (4, 2),
    ProjectileTypeId.FIRE_BULLETS: (4, 2),
    ProjectileTypeId.ION_RIFLE: (4, 2),
}

BEAM_TYPES = frozenset(
    {
        ProjectileTypeId.ION_RIFLE,
        ProjectileTypeId.ION_MINIGUN,
        ProjectileTypeId.ION_CANNON,
        ProjectileTypeId.SHRINKIFIER,
        ProjectileTypeId.FIRE_BULLETS,
        ProjectileTypeId.BLADE_GUN,
        ProjectileTypeId.SPLITTER_GUN,
    }
)
