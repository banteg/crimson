from __future__ import annotations

import math

from grim.assets import TextureId
from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rl

from ...effects import EffectEntry, ParticleStyleId
from ...effects_atlas import EffectId
from . import viewport
from .atlas import effect_cell_src, effect_cell_src_inset
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx


def draw_particle_pool(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
) -> None:
    frame = render_ctx.frame
    texture = frame.resources.texture(TextureId.PARTICLES)

    particles = frame.state.particles.entries
    if not any(entry.active for entry in particles):
        return

    scale = viewport.view_scale_avg(view_scale)

    src_large = effect_cell_src_inset(texture, 13)
    src_normal = effect_cell_src_inset(texture, 12)
    src_style_8 = effect_cell_src_inset(texture, 2)
    if src_normal is None or src_style_8 is None:
        return

    flame_glow_enabled = frame.config.display.flame_glow_enabled if frame.config is not None else True

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)

    if flame_glow_enabled and src_large is not None:
        alpha_byte = int(0.065 * 255.0 + 0.5)
        tint = rl.Color(255, 255, 255, alpha_byte)
        for idx, entry in enumerate(particles):
            if not entry.active or (idx % 2) or int(entry.style_id) == int(ParticleStyleId.BUBBLEGUN):
                continue
            radius = (math.sin((1.0 - float(entry.intensity)) * 1.5707964) + 0.1) * 55.0 + 4.0
            radius = max(radius, 16.0)
            size = max(0.0, radius * 2.0 * scale)
            if size <= 0.0:
                continue
            screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rl.draw_texture_pro(texture, src_large, dst, origin, 0.0, tint)

    for entry in particles:
        if not entry.active or int(entry.style_id) == int(ParticleStyleId.BUBBLEGUN):
            continue
        radius = math.sin((1.0 - float(entry.intensity)) * 1.5707964) * 24.0
        if int(entry.style_id) == int(ParticleStyleId.BLOW_TORCH):
            radius *= 0.8
        radius = max(radius, 2.0)
        size = max(0.0, radius * 2.0 * scale)
        if size <= 0.0:
            continue
        screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
        dst = rl.Rectangle(screen.x, screen.y, size, size)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        rotation_deg = float(entry.spin) * _RAD_TO_DEG
        tint = RGBA(entry.scale_x, entry.scale_y, entry.scale_z, float(entry.age)).to_rl()
        rl.draw_texture_pro(texture, src_normal, dst, origin, rotation_deg, tint)

    for entry in particles:
        if not entry.active or int(entry.style_id) != int(ParticleStyleId.BUBBLEGUN):
            continue
        wobble = math.sin(float(entry.spin)) * 3.0
        half_h = (wobble + 15.0) * float(entry.scale_x) * 7.0
        half_w = (15.0 - wobble) * float(entry.scale_x) * 7.0
        w = max(0.0, half_w * 2.0 * scale)
        h = max(0.0, half_h * 2.0 * scale)
        if w <= 0.0 or h <= 0.0:
            continue
        screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
        dst = rl.Rectangle(screen.x, screen.y, w, h)
        origin = rl.Vector2(w * 0.5, h * 0.5)
        tint = rl.Color(255, 255, 255, int(float(entry.age) * 255.0 + 0.5))
        rl.draw_texture_pro(texture, src_style_8, dst, origin, 0.0, tint)

    rl.end_blend_mode()


def draw_sprite_effect_pool(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
) -> None:
    frame = render_ctx.frame
    if frame.config is not None and not frame.config.display.smoke_enabled:
        return
    texture = frame.resources.texture(TextureId.PARTICLES)

    effects = frame.state.sprite_effects.entries
    if not any(entry.active for entry in effects):
        return

    src = effect_cell_src(texture, EffectId.EXPLOSION_PUFF)
    if src is None:
        return
    scale = viewport.view_scale_avg(view_scale)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
    for entry in effects:
        if not entry.active:
            continue
        size = float(entry.scale) * scale
        if size <= 0.0:
            continue
        screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
        dst = rl.Rectangle(screen.x, screen.y, size, size)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        rotation_deg = float(entry.rotation) * _RAD_TO_DEG
        tint = entry.color.to_rl()
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)
    rl.end_blend_mode()


def draw_effect_pool(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
) -> None:
    frame = render_ctx.frame
    texture = frame.resources.texture(TextureId.PARTICLES)

    effects = frame.state.effects.entries
    if not any(entry.flags and entry.age >= 0.0 for entry in effects):
        return

    scale = viewport.view_scale_avg(view_scale)

    def draw_entry(entry: EffectEntry) -> None:
        effect_id = int(entry.effect_id)
        src = effect_cell_src_inset(texture, effect_id)
        if src is None:
            return

        screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)

        half_w = float(entry.half_width)
        half_h = float(entry.half_height)
        local_scale = float(entry.scale)
        w = max(0.0, half_w * 2.0 * local_scale * scale)
        h = max(0.0, half_h * 2.0 * local_scale * scale)
        if w <= 0.0 or h <= 0.0:
            return

        rotation_deg = float(entry.rotation) * _RAD_TO_DEG
        tint = entry.color.to_rl()

        dst = rl.Rectangle(screen.x, screen.y, float(w), float(h))
        origin = rl.Vector2(float(w) * 0.5, float(h) * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
    for entry in effects:
        if not entry.flags or entry.age < 0.0:
            continue
        if int(entry.flags) & 0x40:
            draw_entry(entry)
    rl.end_blend_mode()

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for entry in effects:
        if not entry.flags or entry.age < 0.0:
            continue
        if not (int(entry.flags) & 0x40):
            draw_entry(entry)
    rl.end_blend_mode()
