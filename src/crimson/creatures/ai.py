from __future__ import annotations

"""Creature AI helpers.

Ported from `creature_update_all` (`FUN_00426220`).
"""

from dataclasses import dataclass
import math
from typing import Callable, Protocol, Sequence

from .spawn import CreatureFlags

__all__ = [
    "CreatureAIUpdate",
    "creature_ai7_tick_link_timer",
    "creature_ai_update_target",
]


class PositionLike(Protocol):
    x: float
    y: float


class CreatureLinkLike(PositionLike, Protocol):
    hp: float


class CreatureAIStateLike(CreatureLinkLike, Protocol):
    flags: CreatureFlags
    ai_mode: int
    link_index: int
    target_offset_x: float | None
    target_offset_y: float | None
    phase_seed: float
    orbit_angle: float
    orbit_radius: float
    heading: float

    target_x: float
    target_y: float
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
    player_x: float,
    player_y: float,
    creatures: Sequence[CreatureLinkLike],
    dt: float,
) -> CreatureAIUpdate:
    """Compute the target position + heading for one creature.

    Updates:
    - `target_x/target_y`
    - `target_heading`
    - `force_target`
    - `ai_mode` (may reset to 0 in some modes)
    - `orbit_radius` (AI7 non-link timer uses it as a countdown)
    """

    dx = player_x - creature.x
    dy = player_y - creature.y
    dist_to_player = math.hypot(dx, dy)

    orbit_phase = float(int(creature.phase_seed)) * 3.7 * math.pi
    move_scale = 1.0
    self_damage: float | None = None

    creature.force_target = 0

    ai_mode = creature.ai_mode
    if ai_mode == 0:
        if dist_to_player > 800.0:
            creature.target_x = player_x
            creature.target_y = player_y
        else:
            creature.target_x = player_x + math.cos(orbit_phase) * dist_to_player * 0.85
            creature.target_y = player_y + math.sin(orbit_phase) * dist_to_player * 0.85
    elif ai_mode == 8:
        creature.target_x = player_x + math.cos(orbit_phase) * dist_to_player * 0.9
        creature.target_y = player_y + math.sin(orbit_phase) * dist_to_player * 0.9
    elif ai_mode == 1:
        if dist_to_player > 800.0:
            creature.target_x = player_x
            creature.target_y = player_y
        else:
            creature.target_x = player_x + math.cos(orbit_phase) * dist_to_player * 0.55
            creature.target_y = player_y + math.sin(orbit_phase) * dist_to_player * 0.55
    elif ai_mode == 3:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target_x = link.x + float(creature.target_offset_x or 0.0)
            creature.target_y = link.y + float(creature.target_offset_y or 0.0)
        else:
            creature.ai_mode = 0
    elif ai_mode == 5:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target_x = link.x + float(creature.target_offset_x or 0.0)
            creature.target_y = link.y + float(creature.target_offset_y or 0.0)
            dist_to_target = math.hypot(creature.target_x - creature.x, creature.target_y - creature.y)
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
            creature.target_x = player_x
            creature.target_y = player_y
        else:
            creature.target_x = player_x + math.cos(orbit_phase) * dist_to_player * 0.85
            creature.target_y = player_y + math.sin(orbit_phase) * dist_to_player * 0.85
    elif ai_mode == 7:
        if (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.link_index > 0:
            creature.target_x = creature.x
            creature.target_y = creature.y
        elif not (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.orbit_radius > 0.0:
            creature.target_x = creature.x
            creature.target_y = creature.y
            creature.orbit_radius -= dt
        else:
            creature.ai_mode = 0
    elif ai_mode == 6:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = 0
        else:
            angle = float(creature.orbit_angle) + float(creature.heading)
            creature.target_x = link.x + math.cos(angle) * float(creature.orbit_radius)
            creature.target_y = link.y + math.sin(angle) * float(creature.orbit_radius)

    dist_to_target = math.hypot(creature.target_x - creature.x, creature.target_y - creature.y)
    if dist_to_target < 40.0 or dist_to_target > 400.0:
        creature.force_target = 1

    if creature.force_target or creature.ai_mode == 2:
        creature.target_x = player_x
        creature.target_y = player_y

    creature.target_heading = math.atan2(creature.target_y - creature.y, creature.target_x - creature.x) + math.pi / 2.0
    return CreatureAIUpdate(move_scale=move_scale, self_damage=self_damage)
