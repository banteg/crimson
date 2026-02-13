from __future__ import annotations

import math

import pyray as rl

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp

from ...projectiles import ProjectileTypeId
from ...sim.world_defs import KNOWN_PROJ_FRAMES
from .common import proj_origin
from .types import ProjectileDrawCtx


def draw_pulse_gun(ctx: ProjectileDrawCtx) -> bool:
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
        origin = proj_origin(ctx.proj, ctx.pos)
        dist = origin.distance_to(ctx.pos)

        desired_size = dist * 0.16 * ctx.scale
        if desired_size <= 1e-3:
            return True
        sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
        if sprite_scale <= 1e-6:
            return True

        tint = RGBA(0.1, 0.6, 0.2, alpha * 0.7).to_rl()
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        renderer._draw_atlas_sprite(
            ctx.texture,
            grid=grid,
            frame=frame,
            pos=ctx.screen_pos,
            scale=sprite_scale,
            rotation_rad=ctx.angle,
            tint=tint,
        )
        rl.end_blend_mode()
        return True

    fade = clamp(life * 2.5, 0.0, 1.0)
    fade_alpha = fade * alpha
    if fade_alpha <= 1e-3:
        return True

    desired_size = 56.0 * ctx.scale
    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
    if sprite_scale <= 1e-6:
        return True

    tint = RGBA(1.0, 1.0, 1.0, fade_alpha).to_rl()
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    renderer._draw_atlas_sprite(
        ctx.texture,
        grid=grid,
        frame=frame,
        pos=ctx.screen_pos,
        scale=sprite_scale,
        rotation_rad=ctx.angle,
        tint=tint,
    )
    rl.end_blend_mode()
    return True


def draw_splitter_or_blade(ctx: ProjectileDrawCtx) -> bool:
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

    origin = proj_origin(ctx.proj, ctx.pos)
    dist = origin.distance_to(ctx.pos)

    desired_size = min(dist, 20.0) * ctx.scale
    if desired_size <= 1e-3:
        return True

    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
    if sprite_scale <= 1e-6:
        return True

    rotation_rad = ctx.angle
    rgb = (1.0, 1.0, 1.0)
    if type_id == int(ProjectileTypeId.BLADE_GUN):
        rotation_rad = float(int(ctx.proj_index)) * 0.1 - float(renderer.elapsed_ms) * 0.1
        rgb = (0.8, 0.8, 0.8)

    tint = RGBA(rgb[0], rgb[1], rgb[2], float(ctx.alpha)).to_rl()
    renderer._draw_atlas_sprite(
        ctx.texture,
        grid=grid,
        frame=frame,
        pos=ctx.screen_pos,
        scale=sprite_scale,
        rotation_rad=rotation_rad,
        tint=tint,
    )
    return True


def draw_plague_spreader(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    if int(ctx.type_id) != int(ProjectileTypeId.PLAGUE_SPREADER):
        return False
    texture = ctx.texture
    if texture is None:
        return False

    grid = 4
    frame = 2
    cell_w = float(texture.width) / float(grid)

    alpha = float(ctx.alpha)
    life = float(ctx.life)
    if life >= 0.4:
        tint = RGBA(1.0, 1.0, 1.0, alpha).to_rl()

        def draw_plague_quad(*, pos: Vec2, size: float) -> None:
            size = float(size)
            if size <= 1e-3:
                return
            desired_size = size * ctx.scale
            sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
            if sprite_scale <= 1e-6:
                return
            pos_screen = renderer.world_to_screen(pos)
            renderer._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                pos=pos_screen,
                scale=sprite_scale,
                rotation_rad=0.0,
                tint=tint,
            )

        draw_plague_quad(pos=ctx.pos, size=60.0)

        offset = Vec2.from_heading(ctx.angle + math.pi) * 15.0
        draw_plague_quad(
            pos=ctx.pos + offset,
            size=60.0,
        )

        phase = float(int(ctx.proj_index)) + float(renderer.elapsed_ms) * 0.01
        cos_phase = math.cos(phase)
        sin_phase = math.sin(phase)
        draw_plague_quad(
            pos=ctx.pos.offset(dx=cos_phase * cos_phase - 5.0, dy=sin_phase * 11.0 - 5.0),
            size=52.0,
        )

        phase_120 = phase + 2.0943952
        sin_phase_120 = math.sin(phase_120)
        draw_plague_quad(
            pos=ctx.pos + Vec2.from_polar(phase_120, 10.0),
            size=62.0,
        )

        phase_240 = phase + 4.1887903
        draw_plague_quad(
            pos=ctx.pos + Vec2(math.cos(phase_240) * 10.0, math.sin(phase_240) * sin_phase_120),
            size=62.0,
        )
        return True

    fade = clamp(life * 2.5, 0.0, 1.0)
    fade_alpha = fade * alpha
    if fade_alpha <= 1e-3:
        return True

    desired_size = (fade * 40.0 + 32.0) * ctx.scale
    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
    if sprite_scale <= 1e-6:
        return True

    tint = RGBA(1.0, 1.0, 1.0, fade_alpha).to_rl()
    renderer._draw_atlas_sprite(
        texture,
        grid=grid,
        frame=frame,
        pos=ctx.screen_pos,
        scale=sprite_scale,
        rotation_rad=0.0,
        tint=tint,
    )
    return True


__all__ = ["draw_plague_spreader", "draw_pulse_gun", "draw_splitter_or_blade"]
