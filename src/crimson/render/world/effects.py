from __future__ import annotations

import math
from contextlib import nullcontext
from itertools import groupby

from grim.assets import TextureId
from grim.blend import additive_blend
from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2
from grim.shaders import glint_scope

from ...effects import EffectEntry, ParticleStyleId
from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId
from ..rtx.effects import SPRITE_SHAPES, EffectShape, draw_sprite, sprite_batch
from ..rtx.explosion_shell import explosion_shell
from ..rtx.mode import RtxRenderMode
from . import viewport
from .atlas import effect_cell_src, effect_cell_src_inset
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx
from .creatures import draw_centered_quad

# The freeze shatter's ice, which RTX lights as ice.
_ICE_EFFECTS = frozenset({EffectId.FREEZE_SHATTER, EffectId.FREEZE_SHARD_0, EffectId.FREEZE_SHARD_1, EffectId.FREEZE_SHARD_2})


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

    with additive_blend():

        with sprite_batch() as batch:
            if flame_glow_enabled and src_large is not None:
                alpha_byte = int(0.065 * 255.0 + 0.5)
                tint = rl_color(255, 255, 255, alpha_byte)
                for idx, entry in enumerate(particles):
                    if not entry.active or (idx % 2) or int(entry.style_id) == int(ParticleStyleId.BUBBLEGUN):
                        continue
                    radius = (math.sin((1.0 - float(entry.intensity)) * 1.5707964) + 0.1) * 55.0 + 4.0
                    radius = max(radius, 16.0)
                    size = max(0.0, radius * 2.0 * scale)
                    if size <= 0.0:
                        continue
                    screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
                    dst = rl_rectangle(screen.x, screen.y, size, size)
                    origin = rl_vector2(size * 0.5, size * 0.5)
                    if frame.rtx_mode is RtxRenderMode.RTX:
                        draw_sprite(
                            EffectShape.GLOW,
                            center=screen,
                            width=size,
                            height=size,
                            color=RGBA(1.0, 1.0, 1.0, alpha_byte / 255.0),
                            batch=batch,
                        )
                    else:
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
            dst = rl_rectangle(screen.x, screen.y, size, size)
            origin = rl_vector2(size * 0.5, size * 0.5)
            rotation_deg = float(entry.rotation) * _RAD_TO_DEG
            tint = RGBA(entry.color_r, entry.color_g, entry.color_b, float(entry.color_a)).to_rl()
            rl.draw_texture_pro(texture, src_normal, dst, origin, rotation_deg, tint)

        for entry in particles:
            if not entry.active or int(entry.style_id) != int(ParticleStyleId.BUBBLEGUN):
                continue
            wobble = math.sin(float(entry.rotation)) * 3.0
            half_h = (wobble + 15.0) * float(entry.color_r) * 7.0
            half_w = (15.0 - wobble) * float(entry.color_r) * 7.0
            w = max(0.0, half_w * 2.0 * scale)
            h = max(0.0, half_h * 2.0 * scale)
            if w <= 0.0 or h <= 0.0:
                continue
            screen = viewport.world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
            dst = rl_rectangle(screen.x, screen.y, w, h)
            origin = rl_vector2(w * 0.5, h * 0.5)
            tint = rl_color(255, 255, 255, int(float(entry.color_a) * 255.0 + 0.5))
            rl.draw_texture_pro(texture, src_style_8, dst, origin, 0.0, tint)



def draw_sprite_effect_pool(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
) -> None:
    frame = render_ctx.frame
    if frame.rtx_mode is RtxRenderMode.RTX and frame.smoke is not None and frame.smoke.available:
        return
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
        dst = rl_rectangle(screen.x, screen.y, size, size)
        origin = rl_vector2(size * 0.5, size * 0.5)
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

    pool = frame.state.effects
    effects = (*pool.entries, *pool.overflow_entries) if pool.overflow_entries else pool.entries
    fireball_slots: set[int] = set()
    if frame.rtx_mode is RtxRenderMode.RTX:
        archived = []
        for visual in pool.explosion_visuals:
            shell = explosion_shell(visual.age, visual.scale) if visual.emit_light and visual.ring_spawned else None
            if shell is not None:
                archived.append(
                    EffectEntry(
                        effect_id=EffectId.RING,
                        pos=visual.pos,
                        age=0.0,
                        flags=0x19,
                        half_width=shell.radius,
                        half_height=shell.radius,
                        scale=1.0,
                        color=RGBA(190 / 255, 163 / 255, 122 / 255, shell.alpha),
                    ),
                )
            if not visual.emit_light or not 0.0 <= visual.age < visual.lifetime:
                continue
            for sprite in visual.fireballs:
                if sprite.native is not None:
                    fireball_slots.add(id(sprite.native))
                archived.append(sprite.sample(visual.fireball_age))
        effects = (*effects, *archived)
    if not any(entry.flags and entry.age >= 0.0 for entry in effects):
        return

    scale = viewport.view_scale_avg(view_scale)

    # Lit explosions use the warm shell above; rocket, freeze and shield rings
    # keep their native timing and draw through the shared linear-light profile.
    pressure_rings = (
        {id(ring) for v in pool.explosion_visuals if v.emit_light and (ring := v.active_ring) is not None}
        if frame.rtx_mode is RtxRenderMode.RTX
        else set()
    )
    # RTX lights the freeze shatter's cubes and shards as ice, in their places among the effects.
    lighting = frame.creature_lighting if frame.rtx_mode is RtxRenderMode.RTX else None

    def draw_entry(entry: EffectEntry) -> None:
        if (
            frame.rtx_mode is RtxRenderMode.RTX
            and frame.smoke is not None
            and frame.smoke.available
            and entry.effect_id == EffectId.EXPLOSION_PUFF
        ):
            return
        if id(entry) in fireball_slots:
            return
        if id(entry) in pressure_rings and int(entry.effect_id) == int(EffectId.RING):
            return
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

        if lighting is not None and effect_id in _ICE_EFFECTS:
            batch.end()
            with lighting.scope(texture=texture, restore_shader=frame.resources.alpha_test.shader,
                                ice=EFFECT_ID_ATLAS_TABLE_BY_ID[effect_id].grid):
                draw_centered_quad(texture, src, screen, w, h, float(entry.rotation), tint)
            return

        shape = SPRITE_SHAPES.get(effect_id)
        # The same atlas cell supplies an explosion's stationary flash and the
        # moving bonus glints. Preserve the latter's asymmetric textured rays.
        if effect_id == EffectId.BURST and not entry.flags & 0x4:
            shape = EffectShape.BURST
        if (
            frame.rtx_mode is RtxRenderMode.RTX
            and shape is not None
            and not (shape in (EffectShape.GLOW, EffectShape.AURA, EffectShape.BURST) and entry.flags & 0x40)
        ):
            draw_sprite(
                shape, center=screen, width=w, height=h, color=entry.color, rotation=float(entry.rotation), batch=batch,
            )
            return
        batch.end()
        dst = rl_rectangle(screen.x, screen.y, float(w), float(h))
        origin = rl_vector2(float(w) * 0.5, float(h) * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
    with sprite_batch() as batch:
        for entry in effects:
            if not entry.flags or entry.age < 0.0:
                continue
            if int(entry.flags) & 0x40:
                draw_entry(entry)
    rl.end_blend_mode()

    with additive_blend(), sprite_batch() as batch:
        additive = (entry for entry in effects if entry.flags and entry.age >= 0.0 and not entry.flags & 0x40)
        for glints, entries in groupby(additive, key=lambda entry: (
            frame.rtx_mode is RtxRenderMode.RTX and entry.effect_id == EffectId.BURST and bool(entry.flags & 0x4)
        )):
            # Preserve draw order and flush analytic work before changing the
            # enclosing textured shader. Consecutive glints share one scope.
            batch.end()
            with glint_scope() if glints else nullcontext():
                for entry in entries:
                    draw_entry(entry)
                batch.end()
