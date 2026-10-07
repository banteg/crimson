"""Creature AI helpers.

Ported from `creature_update_all`.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from functools import lru_cache
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike

from ..math_parity import (
    NATIVE_PI,
    f32,
    f32_vec2,
    heading_from_delta_f32,
    x87_pc24_add,
    x87_pc24_distance,
    x87_pc24_mul,
)
from ..rng_caller_static import RngCallerStatic
from .spawn import CreatureAiMode, CreatureFlags

if TYPE_CHECKING:
    from .runtime import CreatureState

__all__ = [
    "CreatureAIUpdate",
    "creature_ai7_tick_link_timer",
    "creature_ai_update_target",
]

_FLAG_STOP_AND_GO = int(CreatureFlags.STOP_AND_GO)



class CreatureAIUpdate(msgspec.Struct, frozen=True):
    move_scale: float
    link_death_damage: float | None = None


def creature_ai7_tick_link_timer(
    creature: CreatureState,
    *,
    dt_ms: int,
    rng: CrandLike,
) -> None:
    """Update AI7's link-index timer behavior (flag 0x80).

    In the original, this runs regardless of the current ai_mode; when the timer
    flips from negative to non-negative, ai_mode is forced to 7 for a short hold.
    """

    if (int(creature.flags) & _FLAG_STOP_AND_GO) == 0:
        return

    if creature.link_index < 0:
        creature.link_index += dt_ms
        if creature.link_index >= 0:
            creature.ai_mode = CreatureAiMode.HOLD_TIMER
            creature.link_index = (
                rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_STOP_AND_GO_HOLD)
                & 0x1FF
            ) + 500
        return

    creature.link_index -= dt_ms
    if creature.link_index < 1:
        creature.link_index = -700 - (
            rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_STOP_AND_GO_RESET)
            & 0x3FF
        )


def resolve_live_link(creatures: Sequence[CreatureState], link_index: int) -> CreatureState | None:
    if 0 <= link_index < len(creatures) and creatures[link_index].hp > 0.0:
        return creatures[link_index]
    return None


@lru_cache(maxsize=384)
def _orbit_direction(phase_seed: int) -> tuple[float, float]:
    # Allocation uses rand & 0x17f; split children use rand & 0xff. Preserve
    # the phase spills and keep trig wide until the distance multiply.
    phase = f32(f32(float(phase_seed) * f32(3.7)) * NATIVE_PI)
    return math.cos(phase), math.sin(phase)


def _orbit_target_f32(*, player_pos: Vec2, phase_seed: int, dist: float, scale: float) -> Vec2:
    orbit_dist = f32(dist)
    orbit_scale = f32(scale)
    cos_phase, sin_phase = _orbit_direction(phase_seed)
    px = f32(player_pos.x)
    py = f32(player_pos.y)
    orbit_x = f32(cos_phase * float(orbit_dist))
    orbit_x = f32(float(orbit_x) * float(orbit_scale))
    orbit_y = f32(sin_phase * float(orbit_dist))
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
    creature: CreatureState,
    *,
    player_pos: Vec2,
    distance_player_pos: Vec2,
    creatures: Sequence[CreatureState],
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

    distance_pos = distance_player_pos
    dist_to_player = x87_pc24_distance(creature.pos, distance_pos)
    move_scale = 1.0
    link_death_damage: float | None = None

    creature.force_target = 0

    ai_mode = creature.ai_mode
    if ai_mode == CreatureAiMode.FLANK_PLAYER:
        if dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                phase_seed=creature.phase_seed,
                dist=dist_to_player,
                scale=0.85,
            )
    elif ai_mode == CreatureAiMode.FLANK_PLAYER_WIDE:
        creature.target = _orbit_target_f32(
            player_pos=player_pos,
            phase_seed=creature.phase_seed,
            dist=dist_to_player,
            scale=0.9,
        )
    elif ai_mode == CreatureAiMode.FLANK_PLAYER_TIGHT:
        if dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                phase_seed=creature.phase_seed,
                dist=dist_to_player,
                scale=0.55,
            )
    elif ai_mode == CreatureAiMode.FOLLOW_LINK:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = _link_target_f32(link_pos=link.pos, offset=(creature.target_offset or Vec2()))
        else:
            creature.ai_mode = CreatureAiMode.FLANK_PLAYER
    elif ai_mode == CreatureAiMode.FOLLOW_LINK_TETHERED:
        link = resolve_live_link(creatures, creature.link_index)
        if link is not None:
            creature.target = _link_target_f32(link_pos=link.pos, offset=(creature.target_offset or Vec2()))
            dist_to_target = x87_pc24_distance(creature.pos, creature.target)
            if dist_to_target <= 64.0:
                move_scale = f32(dist_to_target * 0.015625)
        else:
            creature.ai_mode = CreatureAiMode.FLANK_PLAYER
            link_death_damage = 1000.0

    ai_mode = creature.ai_mode
    if ai_mode == CreatureAiMode.FLANK_PLAYER_LINKED:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = CreatureAiMode.FLANK_PLAYER
            link_death_damage = 1000.0
        elif dist_to_player > 800.0:
            creature.target = f32_vec2(player_pos)
        else:
            creature.target = _orbit_target_f32(
                player_pos=player_pos,
                phase_seed=creature.phase_seed,
                dist=dist_to_player,
                scale=0.85,
            )
    elif ai_mode == CreatureAiMode.HOLD_TIMER:
        if (creature.flags & CreatureFlags.STOP_AND_GO) and creature.link_index > 0:
            creature.target = f32_vec2(creature.pos)
        elif not (creature.flags & CreatureFlags.STOP_AND_GO) and creature.orbit_radius > 0.0:
            creature.target = f32_vec2(creature.pos)
            creature.orbit_radius = f32(float(creature.orbit_radius) - float(dt))
        else:
            creature.ai_mode = CreatureAiMode.FLANK_PLAYER
    elif ai_mode == CreatureAiMode.ORBIT_LINK:
        link = resolve_live_link(creatures, creature.link_index)
        if link is None:
            creature.ai_mode = CreatureAiMode.FLANK_PLAYER
        else:
            angle = x87_pc24_add(float(creature.orbit_angle), float(creature.heading))
            orbit_radius = f32(creature.orbit_radius)
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

    dist_to_target = x87_pc24_distance(creature.pos, creature.target)
    if dist_to_target < 40.0 or dist_to_target > 400.0:
        creature.force_target = 1

    if creature.force_target or creature.ai_mode == CreatureAiMode.CHASE_PLAYER:
        creature.target = f32_vec2(player_pos)

    # Native stores dx/dy deltas into float locals before calling atan2.
    dx = f32(float(creature.target.x) - float(creature.pos.x))
    dy = f32(float(creature.target.y) - float(creature.pos.y))
    creature.target_heading = heading_from_delta_f32(dx=float(dx), dy=float(dy))
    return CreatureAIUpdate(move_scale=f32(move_scale), link_death_damage=link_death_damage)
