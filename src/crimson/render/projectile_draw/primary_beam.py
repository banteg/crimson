from __future__ import annotations

from grim.assets import TextureId
from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from ...creatures.lifecycle import creature_lifecycle_is_collidable
from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID, EffectId
from ...perks import PerkId
from ...perks.helpers import perk_active
from ...projectiles.types import ProjectileTemplateId
from ...render.rtx.beam import draw_beam_fast_stamped_body, draw_beam_fast_stamped_head
from ...render.rtx.mode import RtxRenderMode
from ...sim.world_defs import BEAM_TYPES, ION_TYPES
from ..projectile_render_registry import beam_effect_scale
from .common import RAD_TO_DEG, proj_origin
from .types import ProjectileDrawCtx


def _draw_beam_body_sprites(
    *,
    ctx: ProjectileDrawCtx,
    origin: Vec2,
    direction: Vec2,
    dist: float,
    start: float,
    span: float,
    step: float,
    base_alpha: float,
    streak_rgb: tuple[float, float, float],
    texture: rl.Texture,
    grid: int,
    frame: int,
    sprite_scale: float,
) -> None:
    renderer = ctx.renderer
    s = start
    while s < dist:
        t = (s - start) / span if span > 1e-6 else 1.0
        seg_alpha = t * base_alpha
        if seg_alpha > 1e-3:
            pos = origin + direction * s
            pos_screen = renderer.world_to_screen(pos)
            tint = RGBA(streak_rgb[0], streak_rgb[1], streak_rgb[2], seg_alpha).to_rl()
            renderer._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                pos=pos_screen,
                scale=sprite_scale,
                rotation_rad=0.0,
                tint=tint,
            )
        s += step


def draw_beam_effect(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    resources = renderer.resources
    type_id = int(ctx.type_id)
    texture = ctx.texture
    if type_id not in BEAM_TYPES:
        return False
    if texture is None:
        return False

    # Ion weapons and Fire Bullets use the projs.png streak effect (and Ion adds chain arcs on impact).
    grid = 4
    frame = 2

    is_fire_bullets = type_id == ProjectileTemplateId.FIRE_BULLETS.value
    is_ion = type_id in ION_TYPES

    origin = proj_origin(ctx.proj, ctx.pos)
    beam = ctx.pos - origin
    direction, dist = beam.normalized_with_length()
    if dist <= 1e-6:
        return True

    # In the native renderer, Ion Gun Master increases the chain effect thickness and reach.
    perk_scale = 1.0
    if any(perk_active(player, PerkId.ION_GUN_MASTER) for player in renderer.players):
        perk_scale = 1.2

    effect_scale = beam_effect_scale(type_id)

    alpha = float(ctx.alpha)
    life = float(ctx.life)
    if life >= 0.4:
        base_alpha = alpha
    else:
        fade = clamp(life * 2.5, 0.0, 1.0)
        base_alpha = fade * alpha

    if base_alpha <= 1e-3:
        return True

    streak_rgb = (1.0, 0.6, 0.1) if is_fire_bullets else (0.5, 0.6, 1.0)
    head_rgb = (1.0, 1.0, 0.7)

    # Only draw the last 256 units of the path.
    start = 0.0
    span = dist
    if dist > 256.0:
        start = dist - 256.0
        span = 256.0

    step = min(effect_scale * 3.1, 9.0)
    sprite_scale = effect_scale * ctx.scale

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)

    if renderer.rtx_mode is RtxRenderMode.RTX:
        draw_beam_fast_stamped_body(
            origin_screen=renderer.world_to_screen(origin),
            head_screen=ctx.screen_pos,
            start_dist_units=start,
            span_dist_units=span,
            step_units=step,
            effect_scale=effect_scale,
            scale=ctx.scale,
            base_alpha=base_alpha,
            streak_rgb=streak_rgb,
        )
    else:
        _draw_beam_body_sprites(
            ctx=ctx,
            origin=origin,
            direction=direction,
            dist=dist,
            start=start,
            span=span,
            step=step,
            base_alpha=base_alpha,
            streak_rgb=streak_rgb,
            texture=texture,
            grid=grid,
            frame=frame,
            sprite_scale=sprite_scale,
        )

    if life >= 0.4:
        if renderer.rtx_mode is RtxRenderMode.RTX:
            draw_beam_fast_stamped_head(
                center_screen=ctx.screen_pos,
                rotation_rad=ctx.angle,
                effect_scale=effect_scale,
                scale=ctx.scale,
                base_alpha=base_alpha,
                head_rgb=head_rgb,
                is_fire=is_fire_bullets,
            )
        else:
            head_tint = RGBA(head_rgb[0], head_rgb[1], head_rgb[2], base_alpha).to_rl()
            renderer._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                pos=ctx.screen_pos,
                scale=sprite_scale,
                rotation_rad=ctx.angle,
                tint=head_tint,
            )

        # Fire Bullets renders an extra particles.png overlay in a later pass.
        particles_texture = resources.texture(TextureId.PARTICLES)
        if is_fire_bullets and particles_texture is not None:
            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
            if atlas is not None:
                grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                if grid:
                    cell_w = float(particles_texture.width) / float(grid)
                    cell_h = float(particles_texture.height) / float(grid)
                    frame = int(atlas.frame)
                    col = frame % grid
                    row = frame // grid
                    src = rl.Rectangle(
                        cell_w * float(col),
                        cell_h * float(row),
                        max(0.0, cell_w - 2.0),
                        max(0.0, cell_h - 2.0),
                    )
                    tint = RGBA(1.0, 1.0, 1.0, alpha).to_rl()
                    size = 64.0 * ctx.scale
                    dst = rl.Rectangle(ctx.screen_pos.x, ctx.screen_pos.y, float(size), float(size))
                    origin = rl.Vector2(size * 0.5, size * 0.5)
                    rl.draw_texture_pro(particles_texture, src, dst, origin, ctx.angle * RAD_TO_DEG, tint)
    else:
        # Native draws a small blue "core" at the head during the fade stage (life_timer < 0.4).
        core_rgb = (0.5, 0.6, 1.0)
        if renderer.rtx_mode is RtxRenderMode.RTX:
            draw_beam_fast_stamped_head(
                center_screen=ctx.screen_pos,
                rotation_rad=ctx.angle,
                effect_scale=effect_scale,
                scale=ctx.scale,
                base_alpha=base_alpha,
                head_rgb=core_rgb,
                is_fire=is_fire_bullets,
            )
        else:
            core_tint = RGBA(core_rgb[0], core_rgb[1], core_rgb[2], base_alpha).to_rl()
            renderer._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                pos=ctx.screen_pos,
                scale=ctx.scale,
                rotation_rad=ctx.angle,
                tint=core_tint,
            )

        if is_ion:
            # Native: chain reach is derived from the streak scale (`fVar29 * perk_scale * 40.0`).
            radius = effect_scale * perk_scale * 40.0

            # Native iterates via creature_find_in_radius(pos, radius, start_index) in pool order.
            targets = []
            for creature in renderer.creatures.entries[1:]:
                if not creature.active:
                    continue
                if not creature_lifecycle_is_collidable(creature.lifecycle_stage):
                    continue
                d = ctx.pos.distance_to(creature.pos)
                threshold = float(creature.size) * 0.14285715 + 3.0
                if d - radius < threshold:
                    targets.append(creature)

            # Native uses beam effect scale for strip thickness (10x inner, 14x outer),
            # independent of Ion Gun Master. Perk scaling only affects chain reach.
            inner_half = 10.0 * effect_scale * ctx.scale
            outer_half = 14.0 * effect_scale * ctx.scale
            u = 0.625
            v0 = 0.0
            v1 = 0.25

            glow_targets = []
            rl.rl_set_texture(texture.id)
            rl.rl_begin(rd.RL_QUADS)

            for creature in targets:
                target_screen = renderer.world_to_screen(creature.pos)
                segment = target_screen - ctx.screen_pos
                direction_screen, dlen = segment.normalized_with_length()
                if dlen <= 1e-3:
                    continue
                glow_targets.append(creature)
                side = direction_screen.perp_left()

                # Outer strip (softer).
                side_offset = side * outer_half
                p0 = ctx.screen_pos - side_offset
                p1 = ctx.screen_pos + side_offset
                p2 = target_screen + side_offset
                p3 = target_screen - side_offset

                outer_tint = RGBA(0.5, 0.6, 1.0, base_alpha).to_rl()
                rl.rl_color4ub(outer_tint.r, outer_tint.g, outer_tint.b, outer_tint.a)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(p0.x, p0.y)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(p1.x, p1.y)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(p2.x, p2.y)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(p3.x, p3.y)

                # Inner strip (brighter).
                side_offset = side * inner_half
                p0 = ctx.screen_pos - side_offset
                p1 = ctx.screen_pos + side_offset
                p2 = target_screen + side_offset
                p3 = target_screen - side_offset

                inner_tint = RGBA(0.5, 0.6, 1.0, base_alpha).to_rl()
                rl.rl_color4ub(inner_tint.r, inner_tint.g, inner_tint.b, inner_tint.a)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(p0.x, p0.y)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(p1.x, p1.y)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(p2.x, p2.y)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(p3.x, p3.y)

            rl.rl_end()
            rl.rl_set_texture(0)

            for creature in glow_targets:
                target_screen = renderer.world_to_screen(creature.pos)
                target_tint = RGBA(0.5, 0.6, 1.0, base_alpha).to_rl()
                renderer._draw_atlas_sprite(
                    texture,
                    grid=grid,
                    frame=frame,
                    pos=target_screen,
                    scale=sprite_scale,
                    rotation_rad=0.0,
                    tint=target_tint,
                )

    rl.end_blend_mode()
    return True


__all__ = ["draw_beam_effect"]
