from __future__ import annotations

"""Creature AI helpers.

Ported from `creature_update_all` (`FUN_00426220`).
"""

from dataclasses import dataclass
import math
from typing import Callable, Protocol, Sequence

from grim.geom import Vec2

from .spawn import CreatureFlags

__all__ = [
    "CreatureAIUpdate",
    "creature_ai7_tick_link_timer",
    "creature_ai_update_target",
]


# Native code uses literal `3.1415927` (float32-ish) in creature orbit-phase math.
# Using Python's full-precision `math.pi` here measurably drifts long-run trajectories.
_NATIVE_PI = 3.1415927


class PositionLike(Protocol):
    pos: Vec2


class CreatureLinkLike(PositionLike, Protocol):
    hp: float


class CreatureAIStateLike(CreatureLinkLike, Protocol):
    flags: CreatureFlags
    ai_mode: int
    link_index: int
    target_offset: Vec2 | None
    phase_seed: float
    orbit_angle: float
    orbit_radius: float
    heading: float

    target: Vec2
    target_heading: float
    force_target: int


@dataclass(frozen=True, slots=True)
class CreatureAIUpdate:
    move_scale: float
    self_damage: float | None = None


def creature_ai7_tick_link_timer(creature: CreatureAIStateLike, *, dt_ms: int, rand: Callable[[], int]) -> None:
    """Update AI7's link-index timer behavior (flag 0x80).

    In the original, this runs regardless of the current ai_mode; when the timer
    flips from negative to non-negative, ai_mode is forced to 7 for a short hold.
    """

    if not (creature.flags & CreatureFlags.AI7_LINK_TIMER):
        return

    if creature.link_index < 0:
        creature.link_index += dt_ms
        if creature.link_index >= 0:
            creature.ai_mode = 7
            creature.link_index = (rand() & 0x1FF) + 500
        return

    creature.link_index -= dt_ms
    if creature.link_index < 1:
        creature.link_index = -700 - (rand() & 0x3FF)


def resolve_live_link(creatures: Sequence[CreatureLinkLike], link_index: int) -> CreatureLinkLike | None:
    if 0 <= link_index < len(creatures) and creatures[link_index].hp > 0.0:
        return creatures[link_index]
    return None


def creature_ai_update_target(
    creature: CreatureAIStateLike,
    *,
    player_pos: Vec2,
    creatures: Sequence[CreatureLinkLike],
    dt: float,
) -> CreatureAIUpdate:
    """Compute the target position + heading for one creature.

    Updates:
    - `target`
    - `target_heading`
    - `force_target`
    - `ai_mode` (may reset to 0 in some modes)
    - `orbit_radius` (AI7 non-link timer uses it as a countdown)
    """

    dist_to_player = (player_pos - creature.pos).length()

    orbit_phase = float(int(creature.phase_seed)) * 3.7 * _NATIVE_PI
    orbit_offset = Vec2.from_angle(orbit_phase)
    move_scale = 1.0
    self_damage: float | None = None

    creature.force_target = 0

    ai_mode = creature.ai_mode
    if ai_mode == 0:
        if dist_to_player > 800.0:
            creature.target = player_pos
        else:
            creature.target = player_pos + orbit_offset * (dist_to_player * 0.85)
    elif ai_mode == 8:
        creature.target = player_pos + orbit_offset * (dist_to_player * 0.9)
    elif ai_mode == 1:
        if dist_to_player > 800.0:
            creature.target = player_pos
        else:
            creature.target = player_pos + orbit_offset * (dist_to_player * 0.55)
    elif ai_mode == 3:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = link.pos + (creature.target_offset or Vec2())
        else:
            creature.ai_mode = 0
    elif ai_mode == 5:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = link.pos + (creature.target_offset or Vec2())
            dist_to_target = (creature.target - creature.pos).length()
            if dist_to_target <= 64.0:
                move_scale = dist_to_target * 0.015625
        else:
            creature.ai_mode = 0
            self_damage = 1000.0

    ai_mode = creature.ai_mode
    if ai_mode == 4:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = 0
            self_damage = 1000.0
        elif dist_to_player > 800.0:
            creature.target = player_pos
        else:
            creature.target = player_pos + orbit_offset * (dist_to_player * 0.85)
    elif ai_mode == 7:
        if (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.link_index > 0:
            creature.target = creature.pos
        elif not (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.orbit_radius > 0.0:
            creature.target = creature.pos
            creature.orbit_radius -= dt
        else:
            creature.ai_mode = 0
    elif ai_mode == 6:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = 0
        else:
            angle = float(creature.orbit_angle) + float(creature.heading)
            creature.target = link.pos + Vec2.from_angle(angle) * float(creature.orbit_radius)

    dist_to_target = (creature.target - creature.pos).length()
    if dist_to_target < 40.0 or dist_to_target > 400.0:
        creature.force_target = 1

    if creature.force_target or creature.ai_mode == 2:
        creature.target = player_pos

    creature.target_heading = (creature.target - creature.pos).to_heading()
    return CreatureAIUpdate(move_scale=move_scale, self_damage=self_damage)
