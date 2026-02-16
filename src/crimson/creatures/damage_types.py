from __future__ import annotations

from enum import IntEnum


class CreatureDamageType(IntEnum):
    SELF_TICK = 0
    BULLET = 1
    MELEE = 2
    EXPLOSION = 3
    FIRE = 4
    ION = 7


__all__ = ["CreatureDamageType"]
