from __future__ import annotations

import pyray as rl

from grim.geom import Vec2
from grim.math import clamp

from ...creatures.anim import creature_anim_select_frame
from ...creatures.spawn import CreatureFlags, CreatureTypeId
from ...sim.world_defs import CREATURE_ANIM
from .constants import _RAD_TO_DEG
from .mixin_base import WorldRendererMixinBase


class WorldRendererCreaturesMixin(WorldRendererMixinBase):
    def _draw_creature_sprite(
        self,
        texture: rl.Texture,
        *,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        mirror_long: bool | None = None,
        shadow_alpha: int | None = None,
        pos: Vec2,
        rotation_rad: float,
        scale: float,
        size_scale: float,
        tint: rl.Color,
        shadow: bool = False,
    ) -> None:
        info = CREATURE_ANIM.get(type_id)
        if info is None:
            return
        mirror_flag = info.mirror if mirror_long is None else mirror_long
        # Long-strip mirroring is handled by frame index selection, not texture flips.
        index, _, _ = creature_anim_select_frame(
            phase,
            base_frame=info.base,
            mirror_long=mirror_flag,
            flags=flags,
        )
        if index < 0:
            return

        screen_pos = self.world_to_screen(pos)
        width = float(texture.width) / 8.0 * size_scale * scale
        height = float(texture.height) / 8.0 * size_scale * scale
        src_x = float((index % 8) * (texture.width // 8))
        src_y = float((index // 8) * (texture.height // 8))
        src = rl.Rectangle(src_x, src_y, float(texture.width) / 8.0, float(texture.height) / 8.0)

        rotation_deg = float(rotation_rad * _RAD_TO_DEG)

        if shadow:
            # In the original exe this is a "darken" blend pass gated by fx_detail_0
            # (creature_render_type). We approximate it with a black silhouette draw.
            # The observed pass is slightly bigger than the main sprite and offset
            # down-right by ~1px at default sizes.
            alpha = int(shadow_alpha) if shadow_alpha is not None else int(clamp(float(tint.a) * 0.4, 0.0, 255.0) + 0.5)
            shadow_tint = rl.Color(0, 0, 0, alpha)
            shadow_scale = 1.07
            shadow_w = width * shadow_scale
            shadow_h = height * shadow_scale
            offset = width * 0.035 - 0.7 * scale
            shadow_dst = rl.Rectangle(screen_pos.x + offset, screen_pos.y + offset, shadow_w, shadow_h)
            shadow_origin = rl.Vector2(shadow_w * 0.5, shadow_h * 0.5)
            rl.draw_texture_pro(texture, src, shadow_dst, shadow_origin, rotation_deg, shadow_tint)

        dst = rl.Rectangle(screen_pos.x, screen_pos.y, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)
