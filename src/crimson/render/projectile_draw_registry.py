from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING

import pyray as rl

from grim.geom import Vec2
from grim.math import clamp

from ..effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from ..gameplay import perk_active
from ..perks import PerkId
from ..projectiles import ProjectileTypeId
from ..sim.world_defs import BEAM_TYPES, ION_TYPES, KNOWN_PROJ_FRAMES, PLASMA_PARTICLE_TYPES
from .projectile_render_registry import beam_effect_scale, plasma_projectile_render_config

if TYPE_CHECKING:
    from .world_renderer import WorldRenderer

_RAD_TO_DEG = 57.29577951308232


def _proj_origin(proj: object, fallback: Vec2) -> Vec2:
    origin = getattr(proj, "origin", None)
    if isinstance(origin, Vec2):
        return origin
    return fallback


@dataclass(frozen=True, slots=True)
class ProjectileDrawCtx:
    renderer: WorldRenderer
    proj: object
    proj_index: int
    texture: rl.Texture | None
    type_id: int
    pos: Vec2
    sx: float
    sy: float
    life: float
    angle: float
    scale: float
    alpha: float


def _draw_bullet_trail(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    type_id = int(ctx.type_id)
    if not renderer._is_bullet_trail_type(type_id):
        return False

    life_alpha = int(clamp(float(ctx.life), 0.0, 1.0) * 255.0)
    alpha_byte = int(clamp(float(life_alpha) * float(ctx.alpha), 0.0, 255.0) + 0.5)
    drawn = False

    if renderer.bullet_trail_texture is not None:
        origin = _proj_origin(ctx.proj, ctx.pos)
        sx0, sy0 = renderer.world_to_screen(origin.x, origin.y)
        drawn = renderer._draw_bullet_trail(
            sx0,
            sy0,
            ctx.sx,
            ctx.sy,
            type_id=type_id,
            alpha=alpha_byte,
            scale=ctx.scale,
            angle=ctx.angle,
        )

    if renderer.bullet_texture is not None and float(ctx.life) >= 0.39:
        size = renderer._bullet_sprite_size(type_id, scale=ctx.scale)
        src = rl.Rectangle(0.0, 0.0, float(renderer.bullet_texture.width), float(renderer.bullet_texture.height))
        dst = rl.Rectangle(float(ctx.sx), float(ctx.sy), float(size), float(size))
        origin = rl.Vector2(float(size) * 0.5, float(size) * 0.5)
        tint = rl.Color(220, 220, 220, int(alpha_byte))
        rl.draw_texture_pro(renderer.bullet_texture, src, dst, origin, float(ctx.angle) * _RAD_TO_DEG, tint)
        drawn = True

    return bool(drawn)


def _draw_plasma_particles(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    type_id = int(ctx.type_id)
    if type_id not in PLASMA_PARTICLE_TYPES:
        return False
    if renderer.particles_texture is None:
        return False

    particles_texture = renderer.particles_texture
    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
    if atlas is None:
        return False
    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
    if not grid:
        return False

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

    speed_scale = float(getattr(ctx.proj, "speed_scale", 1.0))
    fx_detail_1 = bool(renderer.config.data.get("fx_detail_1", 0)) if renderer.config is not None else True

    plasma_cfg = plasma_projectile_render_config(type_id)
    rgb = plasma_cfg.rgb
    spacing = plasma_cfg.spacing
    seg_limit = plasma_cfg.seg_limit
    tail_size = plasma_cfg.tail_size
    head_size = plasma_cfg.head_size
    head_alpha_mul = plasma_cfg.head_alpha_mul
    aura_rgb = plasma_cfg.aura_rgb
    aura_size = plasma_cfg.aura_size
    aura_alpha_mul = plasma_cfg.aura_alpha_mul

    if float(ctx.life) >= 0.4:
        # Reconstruct the tail length heuristic used by the native render path.
        seg_count = int(float(getattr(ctx.proj, "base_damage", 0.0)))
        if seg_count < 0:
            seg_count = 0
        seg_count //= 5
        if seg_count > int(seg_limit):
            seg_count = int(seg_limit)

        # The stored projectile angle is rotated by +pi/2 vs travel direction.
        direction = Vec2.from_heading(float(ctx.angle) + math.pi) * speed_scale

        alpha = float(ctx.alpha)
        tail_tint = renderer._color_from_rgba((rgb[0], rgb[1], rgb[2], alpha * 0.4))
        head_tint = renderer._color_from_rgba((rgb[0], rgb[1], rgb[2], alpha * head_alpha_mul))
        aura_tint = renderer._color_from_rgba((aura_rgb[0], aura_rgb[1], aura_rgb[2], alpha * aura_alpha_mul))

        rl.begin_blend_mode(rl.BLEND_ADDITIVE)

        if seg_count > 0:
            size = float(tail_size) * float(ctx.scale)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            step = direction * float(spacing)
            for idx in range(int(seg_count)):
                pos = ctx.pos + step * float(idx)
                px = pos.x
                py = pos.y
                psx, psy = renderer.world_to_screen(px, py)
                dst = rl.Rectangle(float(psx), float(psy), float(size), float(size))
                rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tail_tint)

        size = float(head_size) * float(ctx.scale)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        dst = rl.Rectangle(float(ctx.sx), float(ctx.sy), float(size), float(size))
        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, head_tint)

        if fx_detail_1:
            size = float(aura_size) * float(ctx.scale)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            dst = rl.Rectangle(float(ctx.sx), float(ctx.sy), float(size), float(size))
            rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, aura_tint)

        rl.end_blend_mode()
        return True

    fade = clamp(float(ctx.life) * 2.5, 0.0, 1.0)
    fade_alpha = fade * float(ctx.alpha)
    if fade_alpha > 1e-3:
        tint = renderer._color_from_rgba((1.0, 1.0, 1.0, fade_alpha))
        size = 56.0 * float(ctx.scale)
        dst = rl.Rectangle(float(ctx.sx), float(ctx.sy), float(size), float(size))
        origin = rl.Vector2(size * 0.5, size * 0.5)
        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)
        rl.end_blend_mode()

    return True


def _draw_beam_effect(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    type_id = int(ctx.type_id)
    texture = ctx.texture
    if type_id not in BEAM_TYPES:
        return False
    if texture is None:
        return False

    # Ion weapons and Fire Bullets use the projs.png streak effect (and Ion adds chain arcs on impact).
    grid = 4
    frame = 2

    is_fire_bullets = type_id == int(ProjectileTypeId.FIRE_BULLETS)
    is_ion = type_id in ION_TYPES

    origin = _proj_origin(ctx.proj, ctx.pos)
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
    sprite_scale = effect_scale * float(ctx.scale)

    rl.begin_blend_mode(rl.BLEND_ADDITIVE)

    s = start
    while s < dist:
        t = (s - start) / span if span > 1e-6 else 1.0
        seg_alpha = t * base_alpha
        if seg_alpha > 1e-3:
            pos = origin + direction * s
            px = pos.x
            py = pos.y
            psx, psy = renderer.world_to_screen(px, py)
            tint = renderer._color_from_rgba((streak_rgb[0], streak_rgb[1], streak_rgb[2], seg_alpha))
            renderer._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                x=psx,
                y=psy,
                scale=sprite_scale,
                rotation_rad=float(ctx.angle),
                tint=tint,
            )
        s += step

    if life >= 0.4:
        head_tint = renderer._color_from_rgba((head_rgb[0], head_rgb[1], head_rgb[2], base_alpha))
        renderer._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            x=float(ctx.sx),
            y=float(ctx.sy),
            scale=sprite_scale,
            rotation_rad=float(ctx.angle),
            tint=head_tint,
        )

        # Fire Bullets renders an extra particles.png overlay in a later pass.
        if is_fire_bullets and renderer.particles_texture is not None:
            particles_texture = renderer.particles_texture
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
                    tint = renderer._color_from_rgba((1.0, 1.0, 1.0, alpha))
                    size = 64.0 * float(ctx.scale)
                    dst = rl.Rectangle(float(ctx.sx), float(ctx.sy), float(size), float(size))
                    origin = rl.Vector2(size * 0.5, size * 0.5)
                    rl.draw_texture_pro(particles_texture, src, dst, origin, float(ctx.angle) * _RAD_TO_DEG, tint)
    else:
        # Native draws a small blue "core" at the head during the fade stage (life_timer < 0.4).
        core_tint = renderer._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
        renderer._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            x=float(ctx.sx),
            y=float(ctx.sy),
            scale=1.0 * float(ctx.scale),
            rotation_rad=float(ctx.angle),
            tint=core_tint,
        )

        if is_ion:
            # Native: chain reach is derived from the streak scale (`fVar29 * perk_scale * 40.0`).
            radius = effect_scale * perk_scale * 40.0

            # Native iterates via creature_find_in_radius(pos, radius, start_index) in pool order.
            targets: list[object] = []
            for creature in renderer.creatures.entries[1:]:
                if not creature.active:
                    continue
                if float(getattr(creature, "hitbox_size", 0.0)) <= 5.0:
                    continue
                d = ctx.pos.distance_to(creature.pos)
                threshold = float(creature.size) * 0.14285715 + 3.0
                if d - radius < threshold:
                    targets.append(creature)

            inner_half = 10.0 * perk_scale * float(ctx.scale)
            outer_half = 14.0 * perk_scale * float(ctx.scale)
            u = 0.625
            v0 = 0.0
            v1 = 0.25

            glow_targets: list[object] = []
            rl.rl_set_texture(texture.id)
            rl.rl_begin(rl.RL_QUADS)

            for creature in targets:
                tx, ty = renderer.world_to_screen(float(creature.pos.x), float(creature.pos.y))
                segment = Vec2(float(tx) - float(ctx.sx), float(ty) - float(ctx.sy))
                direction_screen, dlen = segment.normalized_with_length()
                if dlen <= 1e-3:
                    continue
                glow_targets.append(creature)
                side = direction_screen.perp_left()

                # Outer strip (softer).
                half = outer_half
                off = side * half
                off_x = off.x
                off_y = off.y
                x0 = float(ctx.sx) - off_x
                y0 = float(ctx.sy) - off_y
                x1 = float(ctx.sx) + off_x
                y1 = float(ctx.sy) + off_y
                x2 = float(tx) + off_x
                y2 = float(ty) + off_y
                x3 = float(tx) - off_x
                y3 = float(ty) - off_y

                outer_tint = renderer._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
                rl.rl_color4ub(outer_tint.r, outer_tint.g, outer_tint.b, outer_tint.a)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(x0, y0)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(x1, y1)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(x2, y2)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(x3, y3)

                # Inner strip (brighter).
                half = inner_half
                off = side * half
                off_x = off.x
                off_y = off.y
                x0 = float(ctx.sx) - off_x
                y0 = float(ctx.sy) - off_y
                x1 = float(ctx.sx) + off_x
                y1 = float(ctx.sy) + off_y
                x2 = float(tx) + off_x
                y2 = float(ty) + off_y
                x3 = float(tx) - off_x
                y3 = float(ty) - off_y

                inner_tint = renderer._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
                rl.rl_color4ub(inner_tint.r, inner_tint.g, inner_tint.b, inner_tint.a)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(x0, y0)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(x1, y1)
                rl.rl_tex_coord2f(u, v1)
                rl.rl_vertex2f(x2, y2)
                rl.rl_tex_coord2f(u, v0)
                rl.rl_vertex2f(x3, y3)

            rl.rl_end()
            rl.rl_set_texture(0)

            for creature in glow_targets:
                tx, ty = renderer.world_to_screen(float(creature.pos.x), float(creature.pos.y))
                target_tint = renderer._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
                renderer._draw_atlas_sprite(
                    texture,
                    grid=grid,
                    frame=frame,
                    x=float(tx),
                    y=float(ty),
                    scale=sprite_scale,
                    rotation_rad=0.0,
                    tint=target_tint,
                )

    rl.end_blend_mode()
    return True


def _draw_pulse_gun(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    if int(ctx.type_id) != int(ProjectileTypeId.PULSE_GUN):
        return False
    if ctx.texture is None:
        return False

    mapping = KNOWN_PROJ_FRAMES.get(int(ctx.type_id))
    if mapping is None:
        return True
    grid, frame = mapping
    cell_w = float(ctx.texture.width) / float(grid)

    alpha = float(ctx.alpha)
    life = float(ctx.life)
    if life >= 0.4:
        origin = _proj_origin(ctx.proj, ctx.pos)
        dist = origin.distance_to(ctx.pos)

        desired_size = dist * 0.16 * float(ctx.scale)
        if desired_size <= 1e-3:
            return True
        sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
        if sprite_scale <= 1e-6:
            return True

        tint = renderer._color_from_rgba((0.1, 0.6, 0.2, alpha * 0.7))
        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
        renderer._draw_atlas_sprite(
            ctx.texture,
            grid=grid,
            frame=frame,
            x=float(ctx.sx),
            y=float(ctx.sy),
            scale=sprite_scale,
            rotation_rad=float(ctx.angle),
            tint=tint,
        )
        rl.end_blend_mode()
        return True

    fade = clamp(life * 2.5, 0.0, 1.0)
    fade_alpha = fade * alpha
    if fade_alpha <= 1e-3:
        return True

    desired_size = 56.0 * float(ctx.scale)
    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
    if sprite_scale <= 1e-6:
        return True

    tint = renderer._color_from_rgba((1.0, 1.0, 1.0, fade_alpha))
    rl.begin_blend_mode(rl.BLEND_ADDITIVE)
    renderer._draw_atlas_sprite(
        ctx.texture,
        grid=grid,
        frame=frame,
        x=float(ctx.sx),
        y=float(ctx.sy),
        scale=sprite_scale,
        rotation_rad=float(ctx.angle),
        tint=tint,
    )
    rl.end_blend_mode()
    return True


def _draw_splitter_or_blade(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    type_id = int(ctx.type_id)
    if type_id not in (int(ProjectileTypeId.SPLITTER_GUN), int(ProjectileTypeId.BLADE_GUN)):
        return False
    if ctx.texture is None:
        return False

    mapping = KNOWN_PROJ_FRAMES.get(type_id)
    if mapping is None:
        return True
    grid, frame = mapping
    cell_w = float(ctx.texture.width) / float(grid)

    if float(ctx.life) < 0.4:
        return True

    origin = _proj_origin(ctx.proj, ctx.pos)
    dist = origin.distance_to(ctx.pos)

    desired_size = min(dist, 20.0) * float(ctx.scale)
    if desired_size <= 1e-3:
        return True

    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
    if sprite_scale <= 1e-6:
        return True

    rotation_rad = float(ctx.angle)
    rgb = (1.0, 1.0, 1.0)
    if type_id == int(ProjectileTypeId.BLADE_GUN):
        rotation_rad = float(int(ctx.proj_index)) * 0.1 - float(renderer._elapsed_ms) * 0.1
        rgb = (0.8, 0.8, 0.8)

    tint = renderer._color_from_rgba((rgb[0], rgb[1], rgb[2], float(ctx.alpha)))
    renderer._draw_atlas_sprite(
        ctx.texture,
        grid=grid,
        frame=frame,
        x=float(ctx.sx),
        y=float(ctx.sy),
        scale=sprite_scale,
        rotation_rad=rotation_rad,
        tint=tint,
    )
    return True


def _draw_plague_spreader(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    if int(ctx.type_id) != int(ProjectileTypeId.PLAGUE_SPREADER):
        return False
    if ctx.texture is None:
        return False

    grid = 4
    frame = 2
    cell_w = float(ctx.texture.width) / float(grid)

    alpha = float(ctx.alpha)
    life = float(ctx.life)
    if life >= 0.4:
        tint = renderer._color_from_rgba((1.0, 1.0, 1.0, alpha))

        def draw_plague_quad(*, px: float, py: float, size: float) -> None:
            size = float(size)
            if size <= 1e-3:
                return
            desired_size = size * float(ctx.scale)
            sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
            if sprite_scale <= 1e-6:
                return
            psx, psy = renderer.world_to_screen(float(px), float(py))
            renderer._draw_atlas_sprite(
                ctx.texture,
                grid=grid,
                frame=frame,
                x=float(psx),
                y=float(psy),
                scale=sprite_scale,
                rotation_rad=0.0,
                tint=tint,
            )

        draw_plague_quad(px=float(ctx.pos.x), py=float(ctx.pos.y), size=60.0)

        offset = Vec2.from_heading(float(ctx.angle) + math.pi) * 15.0
        draw_plague_quad(
            px=float(ctx.pos.x) + offset.x,
            py=float(ctx.pos.y) + offset.y,
            size=60.0,
        )

        phase = float(int(ctx.proj_index)) + float(renderer._elapsed_ms) * 0.01
        cos_phase = math.cos(phase)
        sin_phase = math.sin(phase)
        draw_plague_quad(
            px=float(ctx.pos.x) + cos_phase * cos_phase - 5.0,
            py=float(ctx.pos.y) + sin_phase * 11.0 - 5.0,
            size=52.0,
        )

        phase_120 = phase + 2.0943952
        sin_phase_120 = math.sin(phase_120)
        draw_plague_quad(
            px=float(ctx.pos.x) + math.cos(phase_120) * 10.0,
            py=float(ctx.pos.y) + sin_phase_120 * 10.0,
            size=62.0,
        )

        phase_240 = phase + 4.1887903
        draw_plague_quad(
            px=float(ctx.pos.x) + math.cos(phase_240) * 10.0,
            py=float(ctx.pos.y) + math.sin(phase_240) * sin_phase_120,
            size=62.0,
        )
        return True

    fade = clamp(life * 2.5, 0.0, 1.0)
    fade_alpha = fade * alpha
    if fade_alpha <= 1e-3:
        return True

    desired_size = (fade * 40.0 + 32.0) * float(ctx.scale)
    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
    if sprite_scale <= 1e-6:
        return True

    tint = renderer._color_from_rgba((1.0, 1.0, 1.0, fade_alpha))
    renderer._draw_atlas_sprite(
        ctx.texture,
        grid=grid,
        frame=frame,
        x=float(ctx.sx),
        y=float(ctx.sy),
        scale=sprite_scale,
        rotation_rad=0.0,
        tint=tint,
    )
    return True


PROJECTILE_DRAW_HANDLERS = (
    _draw_bullet_trail,
    _draw_plasma_particles,
    _draw_beam_effect,
    _draw_pulse_gun,
    _draw_splitter_or_blade,
    _draw_plague_spreader,
)


def draw_projectile_from_registry(ctx: ProjectileDrawCtx) -> bool:
    for handler in PROJECTILE_DRAW_HANDLERS:
        if handler(ctx):
            return True
    return False
