from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import pyray as rl

from crimson.effects import FxQueue, FxQueueRotated
from crimson.effects_atlas import effect_src_rect
from grim.terrain_render import GroundCorpseDecal, GroundDecal, GroundRenderer

__all__ = ["bake_fx_queues", "FxQueueTextures"]


@dataclass(frozen=True, slots=True)
class FxQueueTextures:
    particles: rl.Texture
    bodyset: rl.Texture


def bake_fx_queues(
    ground: GroundRenderer,
    *,
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    textures: FxQueueTextures,
    corpse_frame_for_type: Callable[[int], int],
    corpse_shadow: bool = True,
    clear: bool = True,
) -> tuple[bool, bool]:
    """Bake queued terrain FX into the ground render target (port of `fx_queue_render`)."""

    decals: list[GroundDecal] = []
    for entry in fx_queue.iter_active():
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
                centered=True,
            )
        )

    corpse_decals: list[GroundCorpseDecal] = []
    for entry in fx_queue_rotated.iter_active():
        corpse_decals.append(
            GroundCorpseDecal(
                bodyset_frame=corpse_frame_for_type(entry.creature_type_id),
                top_left=entry.top_left,
                size=entry.scale,
                rotation_rad=entry.rotation,
                tint=entry.color.to_rl(),
            )
        )

    baked_fx = ground.bake_decals(decals)
    baked_corpses = ground.bake_corpse_decals(textures.bodyset, corpse_decals, shadow=corpse_shadow)

    if clear:
        fx_queue.clear()
        fx_queue_rotated.clear()

    return baked_fx, baked_corpses
