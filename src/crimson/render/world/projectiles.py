from __future__ import annotations

import math

from grim.assets import TextureId
from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from ...creatures.lifecycle import creature_lifecycle_is_collidable
from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID, EffectId
from ...math_parity import NATIVE_HALF_PI, f32, f32_vec2, sin_f32, x87_pc24_cos_mul, x87_pc24_sin_mul
from ...perks import PerkId
from ...projectiles.types import Projectile, ProjectileTemplateId, SecondaryProjectileTypeId
from ..rtx.beam import draw_beam_fast_stamped_body, draw_beam_fast_stamped_head
from ..rtx.mode import RtxRenderMode
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx, draw_bullet_trail_quad, draw_late_bullet_pass_sprite, late_bullet_pass_size


def projectile_render(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Port of `projectile_render` (0x00422c70): its passes, each over a whole pool.

    `alpha` is the world transition alpha. Only the Gauss trail ignores it, so
    at zero transition that is all that shows.
    """

    alpha = clamp(float(alpha), 0.0, 1.0)
    _sharpshooter_laser_pass(render_ctx, alpha=alpha)
    _bullet_trail_pass(render_ctx, alpha=alpha)
    if alpha <= 1e-3:
        return
    _plasma_glow_pass(render_ctx, alpha=alpha)
    _projectile_sprite_pass(render_ctx, alpha=alpha)
    _plague_pass(render_ctx, alpha=alpha)
    _fire_bullets_glow_pass(render_ctx, alpha=alpha)
    _bullet_head_pass(render_ctx, alpha=alpha)
    _secondary_glow_pass(render_ctx, alpha=alpha)
    _secondary_sprite_pass(render_ctx, alpha=alpha)
    _secondary_flame_pass(render_ctx, alpha=alpha)


def _flame_glow_enabled(render_ctx: WorldRenderCtx) -> bool:
    config = render_ctx.frame.config
    return config.display.flame_glow_enabled if config is not None else True


def _glow_src(texture: rl.Texture) -> rl.Rectangle:
    """`particles` effect 13, the glow every additive projectile pass selects."""

    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID[int(EffectId.GLOW)]
    grid = SIZE_CODE_GRID[int(atlas.size_code)]
    cell_w = float(texture.width) / float(grid)
    cell_h = float(texture.height) / float(grid)
    frame = int(atlas.frame)
    return rl.Rectangle(
        cell_w * float(frame % grid),
        cell_h * float(frame // grid),
        max(0.0, cell_w - 2.0),
        max(0.0, cell_h - 2.0),
    )


def _draw_quad(
    texture: rl.Texture,
    src: rl.Rectangle,
    *,
    pos: Vec2,
    size: float,
    rgba: RGBA,
    rotation_rad: float = 0.0,
) -> None:
    if rgba.a <= 1e-3 or size <= 1e-3:
        return
    dst = rl.Rectangle(pos.x, pos.y, size, size)
    origin = rl.Vector2(size * 0.5, size * 0.5)
    rl.draw_texture_pro(texture, src, dst, origin, rotation_rad * _RAD_TO_DEG, rgba.to_rl())


def _draw_atlas(
    render_ctx: WorldRenderCtx,
    texture: rl.Texture,
    *,
    grid: int,
    frame: int,
    pos: Vec2,
    size: float,
    rgba: RGBA,
    rotation_rad: float = 0.0,
) -> None:
    """Draw a `size`-wide cell of a `grid`x`grid` atlas centered on screen `pos`."""

    if rgba.a <= 1e-3 or size <= 1e-3:
        return
    cell_w = float(texture.width) / float(grid)
    render_ctx._draw_atlas_sprite(
        texture,
        grid=grid,
        frame=frame,
        pos=pos,
        scale=size / cell_w,
        rotation_rad=rotation_rad,
        tint=rgba.to_rl(),
    )


def _sharpshooter_laser_corners(
    player_pos: Vec2,
    aim_heading: float,
    *,
    camera: Vec2,
) -> tuple[Vec2, Vec2, Vec2, Vec2]:
    """Preserve the native laser's trig products and PC24 corner stores."""

    player_pos = f32_vec2(player_pos)
    aim_heading = f32(aim_heading)
    heading = f32(aim_heading - NATIVE_HALF_PI)
    # Native keeps the far cosine wide, but stores its sine before scaling.
    end = f32_vec2(
        player_pos + Vec2(x87_pc24_cos_mul(heading, 512.0), f32(sin_f32(heading) * 512.0)),
    )
    start_heading = f32(heading - f32(0.150915))
    start = f32_vec2(
        player_pos + Vec2(x87_pc24_cos_mul(start_heading, 15.0), x87_pc24_sin_mul(start_heading, 15.0)),
    )
    half_width = Vec2(
        x87_pc24_cos_mul(aim_heading, f32(1.1)),
        x87_pc24_sin_mul(aim_heading, f32(1.1)),
    )
    camera = f32_vec2(camera)
    start = f32_vec2(start + camera)
    end = f32_vec2(end + camera)
    return (
        f32_vec2(start - half_width),
        f32_vec2(start + half_width),
        f32_vec2(end + half_width),
        f32_vec2(end - half_width),
    )


def _sharpshooter_laser_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Sharpshooter laser sight for each living player."""

    if alpha <= 1e-3:
        return
    if PerkId.SHARPSHOOTER not in render_ctx.frame.state.perks:
        return
    bullet_trail_texture = render_ctx.frame.resources.texture(TextureId.BULLET_TRAIL)
    camera = render_ctx.view.camera
    view_scale = render_ctx.view.view_scale

    alpha = f32(alpha)
    # Grim truncates each scaled float channel; the far slots are black.
    tail_alpha = int(f32(f32(alpha * 0.5) * 255.0))
    head_alpha = int(f32(f32(alpha * f32(0.2)) * 255.0))
    tail = rl.Color(255, 0, 0, tail_alpha)
    head = rl.Color(0, 0, 0, head_alpha)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.rl_set_texture(bullet_trail_texture.id)
    rl.rl_begin(rd.RL_QUADS)

    for player in render_ctx.frame.players:
        if float(player.health) <= 0.0:
            continue
        corners = _sharpshooter_laser_corners(player.pos, player.aim_heading, camera=camera)
        p0, p1, p2, p3 = (point.mul_components(view_scale) for point in corners)

        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(0.0, 0.0)
        rl.rl_vertex2f(p0.x, p0.y)
        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(1.0, 0.0)
        rl.rl_vertex2f(p1.x, p1.y)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(1.0, 0.5)
        rl.rl_vertex2f(p2.x, p2.y)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(0.0, 0.5)
        rl.rl_vertex2f(p3.x, p3.y)

    rl.rl_end()
    rl.rl_set_texture(0)
    rl.end_blend_mode()


def _bullet_trail_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Trail quads for the bullet types (ids up to 7) and the Splitter Gun."""

    for proj in render_ctx.frame.state.projectiles.entries:
        if not proj.active:
            continue
        type_id = int(proj.type_id)
        if not (type_id <= 7 or type_id == ProjectileTemplateId.SPLITTER_GUN):
            continue
        # Native Gauss color slots overwrite life*transition with clamped life.
        trail_alpha = clamp(float(proj.life_timer), 0.0, 1.0)
        if type_id != ProjectileTemplateId.GAUSS_GUN:
            trail_alpha *= alpha
        draw_bullet_trail_quad(
            render_ctx,
            proj.origin,
            proj.pos,
            type_id=type_id,
            alpha=int(clamp(trail_alpha * 255.0, 0.0, 255.0)),
            velocity=proj.vel,
        )


def plasma_trail_segment_count(*, distance: float, speed_scale: float, divisor: float, limit: int) -> int:
    """Recover projectile_render's two integer conversions and signed divide."""

    distance_i = int(float(distance))
    divisor_i = int(float(speed_scale) * float(divisor))
    if distance_i <= 0 or divisor_i <= 0:
        return 0
    return min(distance_i // divisor_i, int(limit))


def _plasma_glow_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Glow trails, heads and auras of the plasma family on `particles`."""

    texture = render_ctx.frame.resources.texture(TextureId.PARTICLES)
    src = _glow_src(texture)
    flame_glow = _flame_glow_enabled(render_ctx)
    scale = render_ctx.view.scale

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for proj in render_ctx.frame.state.projectiles.entries:
        if not proj.active:
            continue
        # rgb, segment divisor and step, segment cap, tail/head/aura sizes and alphas
        match int(proj.type_id):
            case ProjectileTemplateId.PLASMA_RIFLE:
                style = ((1.0, 1.0, 1.0), 2.5, 2.5, 8, 22.0, 56.0, 0.45, 256.0, 0.3)
            case ProjectileTemplateId.PLASMA_MINIGUN:
                style = ((1.0, 1.0, 1.0), 2.1, 2.1, 3, 12.0, 16.0, 0.5, 120.0, 0.15)
            case ProjectileTemplateId.PLASMA_CANNON:
                style = ((1.0, 1.0, 1.0), 3.5, 2.6, 18, 44.0, 84.0, 0.45, 256.0, 0.4)
            case ProjectileTemplateId.SPIDER_PLASMA:
                style = ((0.3, 1.0, 0.3), 2.1, 2.1, 3, 12.0, 16.0, 0.5, 120.0, 0.15)
            case ProjectileTemplateId.SHRINKIFIER:
                style = ((0.3, 0.3, 1.0), 2.1, 2.1, 3, 12.0, 16.0, 0.5, 120.0, 0.15)
            case _:
                continue
        (red, green, blue), divisor, step_len, cap, tail_size, head_size, head_alpha, aura_size, aura_alpha = style
        screen = render_ctx.world_to_screen(proj.pos)
        if float(proj.life_timer) < 0.4:
            fade = clamp(float(proj.life_timer) * 2.5, 0.0, 1.0)
            _draw_quad(texture, src, pos=screen, size=56.0 * scale, rgba=RGBA(1.0, 1.0, 1.0, fade * alpha))
            continue
        # Native converts both operands to signed integers before dividing; the
        # numerator is the rendered origin-to-position distance.
        segments = plasma_trail_segment_count(
            distance=proj.origin.distance_to(proj.pos),
            speed_scale=float(proj.speed_scale),
            divisor=divisor,
            limit=cap,
        )
        # The stored angle is rotated by +pi/2 from the travel direction.
        step = Vec2.from_heading(float(proj.angle) + math.pi) * (float(proj.speed_scale) * step_len)
        for index in range(segments):
            _draw_quad(
                texture,
                src,
                pos=render_ctx.world_to_screen(proj.pos + step * float(index)),
                size=tail_size * scale,
                rgba=RGBA(red, green, blue, alpha * 0.4),
            )
        _draw_quad(texture, src, pos=screen, size=head_size * scale, rgba=RGBA(red, green, blue, alpha * head_alpha))
        if flame_glow:
            _draw_quad(texture, src, pos=screen, size=aura_size * scale, rgba=RGBA(red, green, blue, alpha * aura_alpha))
    rl.end_blend_mode()


def _projectile_sprite_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Pulse, Splitter and Blade sprites and the ion/Fire Bullets streaks on `projs`."""

    texture = render_ctx.frame.resources.texture(TextureId.PROJS)
    scale = render_ctx.view.scale
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for proj_index, proj in enumerate(render_ctx.frame.state.projectiles.entries):
        if not proj.active:
            continue
        life = float(proj.life_timer)
        angle = float(proj.angle)
        screen = render_ctx.world_to_screen(proj.pos)
        dist = proj.origin.distance_to(proj.pos)
        match int(proj.type_id):
            case ProjectileTemplateId.PULSE_GUN:
                if life >= 0.4:
                    size, rgba = dist * 0.16, RGBA(0.1, 0.6, 0.2, alpha * 0.7)
                else:
                    size, rgba = 56.0, RGBA(1.0, 1.0, 1.0, clamp(life * 2.5, 0.0, 1.0) * alpha)
                _draw_atlas(render_ctx, texture, grid=2, frame=0, pos=screen, size=size * scale, rgba=rgba, rotation_rad=angle)
            case ProjectileTemplateId.SPLITTER_GUN:
                if life >= 0.4:
                    _draw_atlas(
                        render_ctx,
                        texture,
                        grid=4,
                        frame=3,
                        pos=screen,
                        size=min(dist, 20.0) * scale,
                        rgba=RGBA(1.0, 1.0, 1.0, alpha),
                        rotation_rad=angle,
                    )
            case ProjectileTemplateId.BLADE_GUN:
                if life >= 0.4:
                    _draw_atlas(
                        render_ctx,
                        texture,
                        grid=4,
                        frame=6,
                        pos=screen,
                        size=min(dist, 20.0) * scale,
                        rgba=RGBA(0.8, 0.8, 0.8, alpha),
                        rotation_rad=float(proj_index) * 0.1 - float(render_ctx.frame.elapsed_ms) * 0.1,
                    )
            case ProjectileTemplateId.ION_MINIGUN:
                _draw_streak(render_ctx, texture, proj, effect_scale=1.05, alpha=alpha, chain=True)
            case ProjectileTemplateId.ION_RIFLE:
                _draw_streak(render_ctx, texture, proj, effect_scale=2.2, alpha=alpha, chain=True)
            case ProjectileTemplateId.ION_CANNON:
                _draw_streak(render_ctx, texture, proj, effect_scale=3.5, alpha=alpha, chain=True)
            case ProjectileTemplateId.FIRE_BULLETS:
                _draw_streak(render_ctx, texture, proj, effect_scale=0.8, alpha=alpha, chain=False)
            case _:
                pass
    rl.end_blend_mode()


def _draw_streak(
    render_ctx: WorldRenderCtx,
    texture: rl.Texture,
    proj: Projectile,
    *,
    effect_scale: float,
    alpha: float,
    chain: bool,
) -> None:
    """Ion and Fire Bullets streak: the last 256 units of the path, then its head.

    After impact the head dims to a small blue core and an ion shot arcs to
    every creature within reach.
    """

    frame = render_ctx.frame
    life = float(proj.life_timer)
    base_alpha = alpha if life >= 0.4 else clamp(life * 2.5, 0.0, 1.0) * alpha
    if base_alpha <= 1e-3:
        return
    direction, dist = (proj.pos - proj.origin).normalized_with_length()
    if dist <= 1e-6:
        return
    scale = render_ctx.view.scale
    screen = render_ctx.world_to_screen(proj.pos)
    streak_rgb = (0.5, 0.6, 1.0) if chain else (1.0, 0.6, 0.1)
    start = max(0.0, dist - 256.0)
    span = dist - start
    step = min(effect_scale * 3.1, 9.0)
    cell = float(texture.width) / 4.0
    rtx = frame.rtx_mode is RtxRenderMode.RTX

    if rtx:
        draw_beam_fast_stamped_body(
            origin_screen=render_ctx.world_to_screen(proj.origin),
            head_screen=screen,
            start_dist_units=start,
            span_dist_units=span,
            step_units=step,
            effect_scale=effect_scale,
            scale=scale,
            base_alpha=base_alpha,
            streak_rgb=streak_rgb,
        )
    else:
        along = start
        while along < dist:
            t = (along - start) / span if span > 1e-6 else 1.0
            _draw_atlas(
                render_ctx,
                texture,
                grid=4,
                frame=2,
                pos=render_ctx.world_to_screen(proj.origin + direction * along),
                size=cell * effect_scale * scale,
                rgba=RGBA(*streak_rgb, t * base_alpha),
            )
            along += step

    head_rgb = (1.0, 1.0, 0.7) if life >= 0.4 else (0.5, 0.6, 1.0)
    if rtx:
        draw_beam_fast_stamped_head(
            center_screen=screen,
            rotation_rad=float(proj.angle),
            effect_scale=effect_scale,
            scale=scale,
            base_alpha=base_alpha,
            head_rgb=head_rgb,
            is_fire=not chain,
        )
    else:
        # The fading core is one unscaled cell whatever the streak's scale.
        head_scale = effect_scale if life >= 0.4 else 1.0
        _draw_atlas(
            render_ctx,
            texture,
            grid=4,
            frame=2,
            pos=screen,
            size=cell * head_scale * scale,
            rgba=RGBA(*head_rgb, base_alpha),
            rotation_rad=float(proj.angle),
        )
    if life >= 0.4 or not chain:
        return

    # Ion Gun Master stretches the chain's reach, not its thickness.
    reach = effect_scale * (1.2 if PerkId.ION_GUN_MASTER in frame.state.perks else 1.0) * 40.0
    tint = RGBA(0.5, 0.6, 1.0, base_alpha).to_rl()
    # Native walks `creature_find_in_radius(pos, reach, 1)`: the inner strip, the
    # outer strip, then the glow on that creature, one creature at a time.
    for creature in frame.creatures.entries[1:]:
        if not creature.active or not creature_lifecycle_is_collidable(creature.death_timer):
            continue
        if proj.pos.distance_to(creature.pos) - reach >= float(creature.size) * 0.14285715 + 3.0:
            continue
        target = render_ctx.world_to_screen(creature.pos)
        side_dir, length = (target - screen).normalized_with_length()
        if length <= 1e-3:
            continue
        side = side_dir.perp_left()
        rl.rl_set_texture(texture.id)
        rl.rl_begin(rd.RL_QUADS)
        for half in (10.0, 14.0):
            offset = side * (half * effect_scale * scale)
            rl.rl_color4ub(tint.r, tint.g, tint.b, tint.a)
            for point, v in (
                (screen - offset, 0.0),
                (screen + offset, 0.25),
                (target + offset, 0.25),
                (target - offset, 0.0),
            ):
                rl.rl_tex_coord2f(0.625, v)
                rl.rl_vertex2f(point.x, point.y)
        rl.rl_end()
        rl.rl_set_texture(0)
        _draw_atlas(
            render_ctx,
            texture,
            grid=4,
            frame=2,
            pos=target,
            size=cell * effect_scale * scale,
            rgba=RGBA(0.5, 0.6, 1.0, base_alpha),
        )


def _plague_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Plague Spreader cloud, darkening what lies under it."""

    texture = render_ctx.frame.resources.texture(TextureId.PROJS)
    scale = render_ctx.view.scale
    # Native switches to D3D8 SRC=ZERO / DST=INVSRCALPHA for this pass.
    blend = (rd.RL_ZERO, rd.RL_ONE_MINUS_SRC_ALPHA, rd.RL_ZERO, rd.RL_ONE, rd.RL_FUNC_ADD, rd.RL_FUNC_ADD)
    rl.rl_set_blend_factors_separate(*blend)
    rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM_SEPARATE)
    rl.rl_set_blend_factors_separate(*blend)
    for proj_index, proj in enumerate(render_ctx.frame.state.projectiles.entries):
        if not proj.active or int(proj.type_id) != ProjectileTemplateId.PLAGUE_SPREADER:
            continue
        life = float(proj.life_timer)
        if life < 0.4:
            fade = clamp(life * 2.5, 0.0, 1.0)
            _draw_atlas(
                render_ctx,
                texture,
                grid=4,
                frame=2,
                pos=render_ctx.world_to_screen(proj.pos),
                size=(fade * 40.0 + 32.0) * scale,
                rgba=RGBA(1.0, 1.0, 1.0, fade * alpha),
            )
            continue
        phase = float(proj_index) + float(render_ctx.frame.elapsed_ms) * 0.01
        phase_120 = phase + 2.0943952
        phase_240 = phase + 4.1887903
        for pos, size in (
            (proj.pos, 60.0),
            (proj.pos + Vec2.from_heading(float(proj.angle) + math.pi) * 15.0, 60.0),
            (proj.pos.offset(dx=math.cos(phase) ** 2 - 5.0, dy=math.sin(phase) * 11.0 - 5.0), 52.0),
            (proj.pos + Vec2.from_polar(phase_120, 10.0), 62.0),
            (proj.pos + Vec2(math.cos(phase_240) * 10.0, math.sin(phase_240) * math.sin(phase_120)), 62.0),
        ):
            _draw_atlas(
                render_ctx,
                texture,
                grid=4,
                frame=2,
                pos=render_ctx.world_to_screen(pos),
                size=size * scale,
                rgba=RGBA(1.0, 1.0, 1.0, alpha),
            )
    rl.end_blend_mode()


def _fire_bullets_glow_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Glow over each Fire Bullets head in flight."""

    texture = render_ctx.frame.resources.texture(TextureId.PARTICLES)
    src = _glow_src(texture)
    scale = render_ctx.view.scale
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for proj in render_ctx.frame.state.projectiles.entries:
        if not proj.active or float(proj.life_timer) < 0.4:
            continue
        if int(proj.type_id) != ProjectileTemplateId.FIRE_BULLETS:
            continue
        _draw_quad(
            texture,
            src,
            pos=render_ctx.world_to_screen(proj.pos),
            size=64.0 * scale,
            rgba=RGBA(1.0, 1.0, 1.0, alpha),
            rotation_rad=float(proj.angle),
        )
    rl.end_blend_mode()


def _bullet_head_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """`bullet_i` heads for every projectile in flight but the plasma pair and Pulse."""

    texture = render_ctx.frame.resources.texture(TextureId.BULLET_I)
    scale = render_ctx.view.scale
    for proj in render_ctx.frame.state.projectiles.entries:
        if not proj.active or float(proj.life_timer) < 0.4:
            continue
        type_id = int(proj.type_id)
        if type_id in (
            ProjectileTemplateId.PLASMA_RIFLE,
            ProjectileTemplateId.PLASMA_MINIGUN,
            ProjectileTemplateId.PULSE_GUN,
        ):
            continue
        draw_late_bullet_pass_sprite(
            texture,
            screen_pos=render_ctx.world_to_screen(proj.pos),
            size=late_bullet_pass_size(type_id, scale=scale),
            angle=float(proj.angle),
            alpha=alpha,
        )


def _secondary_glow_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Shared 140px glow behind every secondary projectile, detonations included."""

    if not _flame_glow_enabled(render_ctx):
        return
    texture = render_ctx.frame.resources.texture(TextureId.PARTICLES)
    src = _glow_src(texture)
    scale = render_ctx.view.scale
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for proj in render_ctx.frame.state.secondary_projectiles.entries:
        if not proj.active:
            continue
        _draw_quad(
            texture,
            src,
            pos=render_ctx.world_to_screen(proj.pos) - Vec2.from_heading(float(proj.angle)) * (5.0 * scale),
            size=140.0 * scale,
            rgba=RGBA(1.0, 1.0, 1.0, alpha * 0.48),
        )
    rl.end_blend_mode()


def _secondary_sprite_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Rocket sprites on `projs`."""

    texture = render_ctx.frame.resources.texture(TextureId.PROJS)
    scale = render_ctx.view.scale
    for proj in render_ctx.frame.state.secondary_projectiles.entries:
        if not proj.active:
            continue
        match int(proj.type_id):
            case SecondaryProjectileTypeId.ROCKET:
                size = 14.0
            case SecondaryProjectileTypeId.HOMING_ROCKET:
                size = 10.0
            case SecondaryProjectileTypeId.ROCKET_MINIGUN:
                size = 8.0
            case _:
                continue
        _draw_atlas(
            render_ctx,
            texture,
            grid=4,
            frame=3,
            pos=render_ctx.world_to_screen(proj.pos),
            size=size * scale,
            rgba=RGBA(0.8, 0.8, 0.8, clamp(alpha * 0.9, 0.0, 1.0)),
            rotation_rad=float(proj.angle),
        )


def _secondary_flame_pass(render_ctx: WorldRenderCtx, *, alpha: float) -> None:
    """Exhaust glow behind each rocket."""

    if not _flame_glow_enabled(render_ctx):
        return
    texture = render_ctx.frame.resources.texture(TextureId.PARTICLES)
    src = _glow_src(texture)
    scale = render_ctx.view.scale
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for proj in render_ctx.frame.state.secondary_projectiles.entries:
        if not proj.active:
            continue
        match int(proj.type_id):
            case SecondaryProjectileTypeId.ROCKET_MINIGUN:
                size, rgba = 30.0, RGBA(0.7, 0.7, 1.0, alpha * 0.158)
            case SecondaryProjectileTypeId.ROCKET:
                size, rgba = 60.0, RGBA(1.0, 1.0, 1.0, alpha * 0.68)
            case SecondaryProjectileTypeId.HOMING_ROCKET:
                size, rgba = 40.0, RGBA(1.0, 1.0, 1.0, alpha * 0.58)
            case _:
                continue
        _draw_quad(
            texture,
            src,
            pos=render_ctx.world_to_screen(proj.pos) - Vec2.from_heading(float(proj.angle)) * (9.0 * scale),
            size=size * scale,
            rgba=rgba,
        )
    rl.end_blend_mode()


def secondary_detonation_pass(render_ctx: WorldRenderCtx) -> None:
    """Detonation flashes; `bonus_render` draws them after the particle pool."""

    texture = render_ctx.frame.resources.texture(TextureId.PARTICLES)
    src = _glow_src(texture)
    scale = render_ctx.view.scale
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    for proj in render_ctx.frame.state.secondary_projectiles.entries:
        if not proj.active or int(proj.type_id) != SecondaryProjectileTypeId.DETONATION:
            continue
        t = clamp(float(proj.detonation_t), 0.0, 1.0)
        fade = 1.0 - t
        screen = render_ctx.world_to_screen(proj.pos)
        det_scale = float(proj.detonation_scale)
        _draw_quad(texture, src, pos=screen, size=det_scale * t * 64.0 * scale, rgba=RGBA(1.0, 0.6, 0.1, fade))
        _draw_quad(texture, src, pos=screen, size=det_scale * t * 200.0 * scale, rgba=RGBA(1.0, 0.6, 0.1, fade * 0.3))
    rl.end_blend_mode()


__all__ = ["plasma_trail_segment_count", "projectile_render", "secondary_detonation_pass"]
