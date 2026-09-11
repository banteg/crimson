from __future__ import annotations

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from ...creatures.anim import creature_anim_is_long_strip, creature_anim_select_flash_frame, creature_anim_select_frame
from ...creatures.spawn import CreatureFlags, CreatureTypeId
from ...math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from ...sim.world_defs import CREATURE_ANIM
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx


def creature_render_tint(
    tint: RGBA,
    *,
    max_hp: float,
    energizer_timer: float,
    lifecycle_stage: float,
    transition: float,
) -> RGBA:
    """Native body tint, including PC24 blend order and lifecycle fading."""
    r, g, b, a = (f32(channel) for channel in tint)
    energy = f32(energizer_timer)
    life = f32(lifecycle_stage)
    if energy > 0.0 and f32(max_hp) < 500.0:
        blend = min(energy, 1.0)
        inverse = x87_pc24_sub(1.0, blend)
        half_blend = x87_pc24_mul(blend, 0.5)
        r = x87_pc24_add(x87_pc24_mul(inverse, r), half_blend)
        g = x87_pc24_add(x87_pc24_mul(inverse, g), half_blend)
        b = x87_pc24_add(x87_pc24_mul(inverse, b), blend)
        a = x87_pc24_add(x87_pc24_mul(inverse, a), blend)
    if life < 0.0:
        a = max(0.0, x87_pc24_add(a, x87_pc24_mul(life, f32(0.1))))
    return RGBA(r, g, b, x87_pc24_mul(a, f32(transition)))


def creature_shadow_alpha(
    tint_alpha: float,
    *,
    flags: CreatureFlags,
    lifecycle_stage: float,
    transition: float,
) -> float:
    """Native shadow alpha before Grim2D packs it into a byte."""
    alpha = x87_pc24_mul(f32(tint_alpha), f32(0.4))
    life = f32(lifecycle_stage)
    if life < 0.0:
        fade = 0.5 if creature_anim_is_long_strip(flags) else f32(0.1)
        alpha = max(0.0, x87_pc24_add(alpha, x87_pc24_mul(life, fade)))
    return x87_pc24_mul(alpha, f32(transition))


def creature_color_byte(channel: float) -> int:
    """Grim2D truncates the scaled channel and keeps its low byte."""
    return int(x87_pc24_mul(f32(channel), 255.0)) & 0xFF


def creature_color_to_rl(tint: RGBA) -> rl.Color:
    return rl.Color(*(creature_color_byte(channel) for channel in tint))


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
