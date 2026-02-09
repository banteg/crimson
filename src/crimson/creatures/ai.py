from __future__ import annotations

"""Creature AI helpers.

Ported from `creature_update_all` (`FUN_00426220`).
"""

from dataclasses import dataclass
import math
from typing import Callable, Protocol, Sequence

from grim.geom import Vec2

from ..math_parity import NATIVE_PI, f32, f32_vec2, heading_from_delta_f32
from .spawn import CreatureFlags

__all__ = [
    "CreatureAIUpdate",
    "creature_ai7_tick_link_timer",
    "creature_ai_update_target",
]


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


def _distance_f32(a: Vec2, b: Vec2) -> float:
    dx = float(b.x) - float(a.x)
    dy = float(b.y) - float(a.y)
    return float(math.sqrt(dx * dx + dy * dy))


def _orbit_target_f32(*, player_pos: Vec2, orbit_phase: float, dist: float, scale: float) -> Vec2:
    orbit_dist = float(dist) * float(scale)
    px = float(player_pos.x)
    py = float(player_pos.y)
    orbit_x = math.cos(float(orbit_phase))
    orbit_y = math.sin(float(orbit_phase))
    return Vec2(
        f32(float(orbit_x) * orbit_dist + px),
        f32(float(orbit_y) * orbit_dist + py),
    )


def _link_target_f32(*, link_pos: Vec2, offset: Vec2) -> Vec2:
    return Vec2(
        f32(float(link_pos.x) + float(offset.x)),
        f32(float(link_pos.y) + float(offset.y)),
    )


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

    dist_to_player = _distance_f32(creature.pos, player_pos)
    orbit_phase = f32(float(int(creature.phase_seed)) * f32(3.7)) * NATIVE_PI
    move_scale = 1.0
    self_damage: float | None = None

    creature.force_target = 0

    ai_mode = creature.ai_mode
    if ai_mode == 0:
        if dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                orbit_phase=orbit_phase,
                dist=dist_to_player,
                scale=0.85,
            )
    elif ai_mode == 8:
        creature.target = _orbit_target_f32(
            player_pos=player_pos,
            orbit_phase=orbit_phase,
            dist=dist_to_player,
            scale=0.9,
        )
    elif ai_mode == 1:
        if dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                orbit_phase=orbit_phase,
                dist=dist_to_player,
                scale=0.55,
            )
    elif ai_mode == 3:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = _link_target_f32(link_pos=link.pos, offset=(creature.target_offset or Vec2()))
        else:
            creature.ai_mode = 0
    elif ai_mode == 5:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = _link_target_f32(link_pos=link.pos, offset=(creature.target_offset or Vec2()))
            dist_to_target = _distance_f32(creature.pos, creature.target)
            if dist_to_target <= 64.0:
                move_scale = f32(dist_to_target * 0.015625)
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
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                orbit_phase=orbit_phase,
                dist=dist_to_player,
                scale=0.85,
            )
    elif ai_mode == 7:
        if (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.link_index > 0:
            creature.target = f32_vec2(creature.pos)
        elif not (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.orbit_radius > 0.0:
            creature.target = f32_vec2(creature.pos)
            creature.orbit_radius = f32(float(creature.orbit_radius) - float(dt))
        else:
            creature.ai_mode = 0
    elif ai_mode == 6:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = 0
        else:
            angle = float(creature.orbit_angle) + float(creature.heading)
            orbit_radius = float(creature.orbit_radius)
            creature.target = Vec2(
                f32(math.cos(angle) * orbit_radius + float(link.pos.x)),
                f32(math.sin(angle) * orbit_radius + float(link.pos.y)),
            )

    dist_to_target = _distance_f32(creature.pos, creature.target)
    if dist_to_target < 40.0 or dist_to_target > 400.0:
        creature.force_target = 1

    if creature.force_target or creature.ai_mode == 2:
        creature.target = f32_vec2(player_pos)

    creature.target_heading = heading_from_delta_f32(
        dx=float(creature.target.x) - float(creature.pos.x),
        dy=float(creature.target.y) - float(creature.pos.y),
    )
    return CreatureAIUpdate(move_scale=f32(move_scale), self_damage=self_damage)
