"""Native `terrain_generate` and `terrain_generate_random`, minus the Grim draw calls.

Both consume the authoritative `crt_rand` stream eagerly and return the stamps the
native functions would draw; the renderer only replays those stamps into its target.

Scope: the port assumes `terrain_texture_failed` is 0. Natively a failed terrain
texture makes `terrain_generate` return before its stamp draws (it binds the quest's
base texture instead), while `terrain_generate_random` still draws its selector
prelude and the eligible unlock rolls: a successful roll delegates to that
draw-free fallback, and the default branch returns without stamping.
"""

from __future__ import annotations

import msgspec

from grim.math import f32
from grim.rand import CallerStatic, CrandLike
from grim.terrain_stamps import TerrainLayers, TerrainStamp, TerrainStampLayer

from ..rng_caller_static import RngCallerStatic
from ..terrain_slots import (
    Q1_TERRAIN_SLOTS,
    Q2_TERRAIN_SLOTS,
    Q3_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    TerrainSlotTriplet,
)
from .state_types import TERRAIN_SIZE

# `0.01f`, the rotation step.
_ROTATION_STEP = f32(0.01)


class TerrainSetup(msgspec.Struct, frozen=True):
    """The ground a run shows: the texture slots and the stamps generated with them."""

    terrain_slots: TerrainSlotTriplet
    layers: TerrainLayers


def _stamp_layer(
    rng: CrandLike,
    density: int,
    rotation_caller: CallerStatic,
    y_caller: CallerStatic,
    x_caller: CallerStatic,
) -> TerrainStampLayer:
    stamps: list[TerrainStamp] = []
    for _ in range(TERRAIN_SIZE * TERRAIN_SIZE * density // 0x80000):
        rotation = f32(float(rng.rand_tagged(rotation_caller) % 314) * _ROTATION_STEP)
        # `terrain_vec2_t(x, y)` takes two `crt_rand()` arguments; MSVC evaluates the y one first.
        y = float(rng.rand_tagged(y_caller) % (TERRAIN_SIZE + 128)) - 64.0
        x = float(rng.rand_tagged(x_caller) % (TERRAIN_SIZE + 128)) - 64.0
        stamps.append(TerrainStamp(rotation=rotation, x=x, y=y))
    return tuple(stamps)


def terrain_generate(rng: CrandLike, terrain_slots: TerrainSlotTriplet) -> TerrainSetup:
    """`terrain_generate(quest)`: base, overlay and detail stamps with the quest's texture slots."""

    base = _stamp_layer(
        rng,
        800,
        RngCallerStatic.TERRAIN_GENERATE_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_BASE_X,
    )
    overlay = _stamp_layer(
        rng,
        35,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_X,
    )
    detail = _stamp_layer(
        rng,
        15,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_X,
    )
    return TerrainSetup(terrain_slots=terrain_slots, layers=TerrainLayers(base=base, overlay=overlay, detail=detail))


def terrain_generate_random(rng: CrandLike, unlock_index: int) -> TerrainSetup:
    """`terrain_generate_random()`: an unlock-gated quest terrain, else its own stamps with slots (0, 1, 0)."""

    # Three `% 7` texture selectors, overwritten with (0, 1, 0) right after.
    rng.rand_tagged(RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_1)
    rng.rand_tagged(RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_2)
    rng.rand_tagged(RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_3)
    # Each roll is drawn only when its unlock threshold passes; the descriptors are quests 4.2, 3.2 and 2.2.
    if unlock_index >= 40 and (rng.rand_tagged(RngCallerStatic.UNLOCK_TERRAIN_Q4) & 7) == 3:
        return terrain_generate(rng, Q4_TERRAIN_SLOTS)
    if unlock_index >= 30 and (rng.rand_tagged(RngCallerStatic.UNLOCK_TERRAIN_Q3) & 7) == 3:
        return terrain_generate(rng, Q3_TERRAIN_SLOTS)
    if unlock_index >= 20 and (rng.rand_tagged(RngCallerStatic.UNLOCK_TERRAIN_Q2) & 7) == 3:
        return terrain_generate(rng, Q2_TERRAIN_SLOTS)

    base = _stamp_layer(
        rng,
        800,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_X,
    )
    overlay = _stamp_layer(
        rng,
        35,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_X,
    )
    detail = _stamp_layer(
        rng,
        15,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_X,
    )
    return TerrainSetup(terrain_slots=Q1_TERRAIN_SLOTS, layers=TerrainLayers(base=base, overlay=overlay, detail=detail))
