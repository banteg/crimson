from __future__ import annotations

from collections.abc import Callable

import msgspec

from crimson.effects_atlas import effect_src_rect
from crimson.sim.terrain_fx import TerrainFxBatch
from grim.raylib_api import rl
from grim.terrain_render import GroundCorpseDecal, GroundDecal, GroundRenderer

__all__ = ["FxQueueTextures", "bake_terrain_fx_batch"]


class FxQueueTextures(msgspec.Struct, frozen=True):
    particles: rl.Texture
    bodyset: rl.Texture


def bake_terrain_fx_batch(
    ground: GroundRenderer,
    *,
    batch: TerrainFxBatch,
    textures: FxQueueTextures,
    corpse_frame_for_type: Callable[[int], int],
) -> tuple[bool, bool]:
    """Bake terrain FX batch into the ground render target (port of `fx_queue_render`)."""

    decals: list[GroundDecal] = []
    for entry in batch.decals:
        src = effect_src_rect(
            entry.effect_id,
            texture_width=float(textures.particles.width),
            texture_height=float(textures.particles.height),
        )
        if src is None:
            continue
        decals.append(
            GroundDecal(
                texture=textures.particles,
                src=rl.Rectangle(*src),
                pos=entry.pos,
                width=entry.width,
                height=entry.height,
                rotation_rad=entry.rotation,
                tint=entry.color.to_rl(),
            ),
        )

    corpse_decals: list[GroundCorpseDecal] = []
    for entry in batch.corpses:
        corpse_decals.append(
            GroundCorpseDecal(
                bodyset_frame=corpse_frame_for_type(entry.creature_type_id),
                top_left=entry.top_left,
                size=entry.scale,
                rotation_rad=entry.rotation,
                tint=entry.color.to_rl(),
            ),
        )

    baked_fx = ground.bake_decals(decals)
    baked_corpses = ground.bake_corpse_decals(textures.bodyset, corpse_decals)
    return baked_fx, baked_corpses
