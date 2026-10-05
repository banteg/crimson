from __future__ import annotations

from enum import IntEnum

CREATURE_LIFECYCLE_ALIVE = 16.0
CREATURE_LIFECYCLE_COLLIDABLE_MIN = 5.0
CREATURE_CORPSE_DESPAWN_LIFECYCLE = -10.0


class CreatureLifecyclePhase(IntEnum):
    ALIVE = 0
    DEATH_STAGING = 1
    CORPSE_FADING = 2
    DESPAWNED = 3


def creature_lifecycle_is_alive(death_timer: float) -> bool:
    return float(death_timer) == CREATURE_LIFECYCLE_ALIVE


def creature_lifecycle_is_collidable(death_timer: float) -> bool:
    return float(death_timer) > CREATURE_LIFECYCLE_COLLIDABLE_MIN


def classify_creature_lifecycle(death_timer: float) -> CreatureLifecyclePhase:
    if creature_lifecycle_is_alive(float(death_timer)):
        return CreatureLifecyclePhase.ALIVE
    if float(death_timer) > 0.0:
        return CreatureLifecyclePhase.DEATH_STAGING
    if float(death_timer) >= CREATURE_CORPSE_DESPAWN_LIFECYCLE:
        return CreatureLifecyclePhase.CORPSE_FADING
    return CreatureLifecyclePhase.DESPAWNED


__all__ = [
    "CREATURE_CORPSE_DESPAWN_LIFECYCLE",
    "CREATURE_LIFECYCLE_ALIVE",
    "CREATURE_LIFECYCLE_COLLIDABLE_MIN",
    "CreatureLifecyclePhase",
    "classify_creature_lifecycle",
    "creature_lifecycle_is_alive",
    "creature_lifecycle_is_collidable",
]
