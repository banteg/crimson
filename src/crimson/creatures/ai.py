from __future__ import annotations

"""Creature AI helpers.

Ported from `creature_update_all` (`FUN_00426220`).
"""

import math
from collections.abc import Sequence
from typing import Protocol

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike

from ..math_parity import (
    NATIVE_PI,
    f32,
    f32_vec2,
    heading_from_delta_f32,
    x87_pc24_add,
    x87_pc24_mul,
)
from ..rng_caller_static import RngCallerStatic
from .spawn import CreatureAiMode, CreatureFlags

__all__ = [
    "CreatureAIUpdate",
    "creature_ai7_tick_link_timer",
    "creature_ai_update_target",
]

_FLAG_AI7_LINK_TIMER = int(CreatureFlags.AI7_LINK_TIMER)


class CreatureAIStateLike(Protocol):
    pos: Vec2
    hp: float
    flags: CreatureFlags
    ai_mode: CreatureAiMode
    link_index: int
    target_offset: Vec2 | None
    phase_seed: int
    orbit_angle: float
    orbit_radius: float
    heading: float

    target: Vec2
    target_heading: float
    force_target: int


class CreatureAIUpdate(msgspec.Struct, frozen=True):
    move_scale: float
    self_damage: float | None = None


def creature_ai7_tick_link_timer(
    creature: CreatureAIStateLike,
    *,
    dt_ms: int,
    rng: CrandLike,
) -> None:
    """Update AI7's link-index timer behavior (flag 0x80).

    In the original, this runs regardless of the current ai_mode; when the timer
    flips from negative to non-negative, ai_mode is forced to 7 for a short hold.
    """

    if (int(creature.flags) & _FLAG_AI7_LINK_TIMER) == 0:
        return

    if creature.link_index < 0:
        creature.link_index += dt_ms
        if creature.link_index >= 0:
            creature.ai_mode = CreatureAiMode.HOLD_TIMER
            creature.link_index = (
                rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_AI7_LINK_TIMER_HOLD)
                & 0x1FF
            ) + 500
        return

    creature.link_index -= dt_ms
    if creature.link_index < 1:
        creature.link_index = -700 - (
            rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_AI7_LINK_TIMER_RESET)
            & 0x3FF
        )


def resolve_live_link(creatures: Sequence[CreatureAIStateLike], link_index: int) -> CreatureAIStateLike | None:
    if 0 <= link_index < len(creatures) and creatures[link_index].hp > 0.0:
        return creatures[link_index]
    return None


def _distance_f32(a: Vec2, b: Vec2) -> float:
    # Gameplay leaves x87 in 24-bit precision mode: the deltas, squares, and
    # sum each round to f32 before fsqrt stores the final distance.
    dx = f32(float(b.x) - float(a.x))
    dy = f32(float(b.y) - float(a.y))
    dx_sq = f32(float(dx) * float(dx))
    dy_sq = f32(float(dy) * float(dy))
    dist_sq = f32(float(dx_sq) + float(dy_sq))
    return f32(math.sqrt(float(dist_sq)))


def _orbit_target_f32(*, player_pos: Vec2, orbit_phase: float, dist: float, scale: float) -> Vec2:
    orbit_dist = f32(float(dist))
    orbit_scale = f32(float(scale))
    phase = f32(float(orbit_phase))
    px = f32(float(player_pos.x))
    py = f32(float(player_pos.y))
    orbit_x = f32(math.cos(float(phase)) * float(orbit_dist))
    orbit_x = f32(float(orbit_x) * float(orbit_scale))
    orbit_y = f32(math.sin(float(phase)) * float(orbit_dist))
    orbit_y = f32(float(orbit_y) * float(orbit_scale))
    return Vec2(
        f32(float(orbit_x) + px),
        f32(float(orbit_y) + py),
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
    distance_player_pos: Vec2 | None = None,
    creatures: Sequence[CreatureAIStateLike],
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

    distance_pos = player_pos if distance_player_pos is None else distance_player_pos
    dist_to_player = _distance_f32(creature.pos, distance_pos)
    orbit_phase = f32(f32(float(creature.phase_seed) * f32(3.7)) * NATIVE_PI)
    move_scale = 1.0
    self_damage: float | None = None

    creature.force_target = 0

    ai_mode = creature.ai_mode
    if ai_mode == CreatureAiMode.ORBIT_PLAYER:
        if dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                orbit_phase=orbit_phase,
                dist=dist_to_player,
                scale=0.85,
            )
    elif ai_mode == CreatureAiMode.ORBIT_PLAYER_WIDE:
        creature.target = _orbit_target_f32(
            player_pos=player_pos,
            orbit_phase=orbit_phase,
            dist=dist_to_player,
            scale=0.9,
        )
    elif ai_mode == CreatureAiMode.ORBIT_PLAYER_TIGHT:
        if dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                orbit_phase=orbit_phase,
                dist=dist_to_player,
                scale=0.55,
            )
    elif ai_mode == CreatureAiMode.FOLLOW_LINK:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = _link_target_f32(link_pos=link.pos, offset=(creature.target_offset or Vec2()))
        else:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    elif ai_mode == CreatureAiMode.FOLLOW_LINK_TETHERED:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = _link_target_f32(link_pos=link.pos, offset=(creature.target_offset or Vec2()))
            dist_to_target = _distance_f32(creature.pos, creature.target)
            if dist_to_target <= 64.0:
                move_scale = f32(dist_to_target * 0.015625)
        else:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
            self_damage = 1000.0

    ai_mode = creature.ai_mode
    if ai_mode == CreatureAiMode.LINK_GUARD:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
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
    elif ai_mode == CreatureAiMode.HOLD_TIMER:
        if (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.link_index > 0:
            creature.target = f32_vec2(creature.pos)
        elif not (creature.flags & CreatureFlags.AI7_LINK_TIMER) and creature.orbit_radius > 0.0:
            creature.target = f32_vec2(creature.pos)
            creature.orbit_radius = f32(float(creature.orbit_radius) - float(dt))
        else:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    elif ai_mode == CreatureAiMode.ORBIT_LINK:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
        else:
            angle = x87_pc24_add(float(creature.orbit_angle), float(creature.heading))
            orbit_radius = f32(float(creature.orbit_radius))
            creature.target = Vec2(
                x87_pc24_add(
                    x87_pc24_mul(math.cos(angle), orbit_radius),
                    float(link.pos.x),
                ),
                x87_pc24_add(
                    x87_pc24_mul(math.sin(angle), orbit_radius),
                    float(link.pos.y),
                ),
            )

    dist_to_target = _distance_f32(creature.pos, creature.target)
    if dist_to_target < 40.0 or dist_to_target > 400.0:
        creature.force_target = 1

    if creature.force_target or creature.ai_mode == CreatureAiMode.CHASE_PLAYER:
        creature.target = f32_vec2(player_pos)

    # Native stores dx/dy deltas into float locals before calling atan2.
    dx = f32(float(creature.target.x) - float(creature.pos.x))
    dy = f32(float(creature.target.y) - float(creature.pos.y))
    creature.target_heading = heading_from_delta_f32(dx=float(dx), dy=float(dy))
    return CreatureAIUpdate(move_scale=f32(move_scale), self_damage=self_damage)
