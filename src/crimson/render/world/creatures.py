from __future__ import annotations

from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from ...creatures.anim import creature_anim_select_flash_frame, creature_anim_select_frame
from ...creatures.spawn import CreatureFlags, CreatureTypeId
from ...sim.world_defs import CREATURE_ANIM
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx


def draw_creature_sprite(
    render_ctx: WorldRenderCtx,
    texture: rl.Texture,
    *,
    type_id: CreatureTypeId,
    flags: CreatureFlags,
    phase: float,
    lifecycle_stage: float = 16.0,
    mirror_long: bool | None = None,
    shadow_alpha: int | None = None,
    pos: Vec2,
    screen_pos: Vec2 | None = None,
    rotation_rad: float,
    scale: float,
    size_scale: float,
    tint: rl.Color,
    shadow: bool = False,
    body: bool = True,
    hit_flash: bool = False,
) -> None:
    info = CREATURE_ANIM.get(type_id)
    if info is None:
        return
    mirror_flag = info.mirror if mirror_long is None else mirror_long
    # Long-strip mirroring is handled by frame index selection, not texture flips.
    select_frame = creature_anim_select_flash_frame if hit_flash else creature_anim_select_frame
    index, _, _ = select_frame(
        phase,
        base_frame=info.base,
        mirror_long=mirror_flag,
        flags=flags,
        lifecycle_stage=lifecycle_stage,
    )
    if index < 0:
        return

    if screen_pos is None:
        screen_pos = render_ctx.world_to_screen(pos)
    width = float(texture.width) / 8.0 * size_scale * scale
    height = float(texture.height) / 8.0 * size_scale * scale
    src_x = float((index % 8) * (texture.width // 8))
    src_y = float((index // 8) * (texture.height // 8))
    src = rl.Rectangle(src_x, src_y, float(texture.width) / 8.0, float(texture.height) / 8.0)

    rotation_deg = float(rotation_rad * _RAD_TO_DEG)

    if shadow:
        # Native darkens with ZERO/INVSRCALPHA; a black silhouette gives the
        # same RGB blend under normal alpha blending. Its 1.07-sized quad is
        # anchored at camera + position - (size / 2 + 0.7). Convert that native
        # top-left position to the centered rectangle expected by Raylib.
        alpha = int(shadow_alpha) if shadow_alpha is not None else int(clamp(float(tint.a) * 0.4, 0.0, 255.0) + 0.5)
        shadow_tint = rl.Color(0, 0, 0, alpha)
        shadow_scale = 1.07
        shadow_w = width * shadow_scale
        shadow_h = height * shadow_scale
        offset = width * 0.035 - 0.7 * scale
        shadow_dst = rl.Rectangle(screen_pos.x + offset, screen_pos.y + offset, shadow_w, shadow_h)
        shadow_origin = rl.Vector2(shadow_w * 0.5, shadow_h * 0.5)
        rl.draw_texture_pro(texture, src, shadow_dst, shadow_origin, rotation_deg, shadow_tint)

    if not body:
        return

    dst = rl.Rectangle(screen_pos.x, screen_pos.y, width, height)
    origin = rl.Vector2(width * 0.5, height * 0.5)
    rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)
    if hit_flash:
        # Native emits two identical additive quads for each flash.
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)
