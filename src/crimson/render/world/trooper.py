from __future__ import annotations

import math
from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID, EffectId
from ...perks import PerkId
from ...perks.helpers import perk_active
from ...weapons import WEAPON_BY_ID
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx

if TYPE_CHECKING:
    from ...sim.state_types import PlayerState

_LAN_PLAYER_RING_RGB: tuple[tuple[int, int, int], ...] = (
    # Match existing trooper torso tint colors for P1/P2.
    (77, 77, 255),
    (255, 140, 89),
    # Distinct colors for P3/P4 (4-player LAN readability).
    (90, 240, 255),
    (255, 120, 230),
)


def lan_player_ring_rgb(player_index: int) -> tuple[int, int, int]:
    idx = max(0, min(len(_LAN_PLAYER_RING_RGB) - 1, int(player_index)))
    return _LAN_PLAYER_RING_RGB[idx]


def draw_lan_player_ring(
    render_ctx: WorldRenderCtx,
    *,
    player: PlayerState,
    screen_pos: Vec2,
    base_size: float,
    scale: float,
    alpha: float,
) -> None:
    if not bool(render_ctx.lan_player_rings_enabled):
        return
    if len(render_ctx.players) <= 1:
        return
    if float(player.health) <= 0.0:
        return
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return

    red, green, blue = lan_player_ring_rgb(int(player.index))
    outer = max(8.0 * scale, float(base_size) * 0.58)
    thickness = max(2.5 * scale, float(base_size) * 0.11)
    inner = max(0.0, outer - thickness)
    glow_outer = outer + max(2.0 * scale, float(base_size) * 0.08)
    segments = max(24, int(outer * 1.5 + 0.5))
    center = rl.Vector2(screen_pos.x, screen_pos.y)
    core = rl.Color(red, green, blue, int(clamp(alpha * 0.9, 0.0, 1.0) * 255.0 + 0.5))
    glow = rl.Color(red, green, blue, int(clamp(alpha * 0.35, 0.0, 1.0) * 255.0 + 0.5))

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.draw_ring(center, inner, outer, 0.0, 360.0, int(segments), core)
    rl.draw_ring(center, outer, glow_outer, 0.0, 360.0, int(segments), glow)
    rl.end_blend_mode()


def draw_player_trooper_sprite(
    render_ctx: WorldRenderCtx,
    texture: rl.Texture,
    player: PlayerState,
    *,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    alpha: float = 1.0,
) -> None:
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return
    sprite_grid = 8
    cell = float(texture.width) / float(sprite_grid) if sprite_grid > 0 else float(texture.width)
    if cell <= 0.0:
        return

    screen_pos = render_ctx._world_to_screen_with(player.pos, camera=camera, view_scale=view_scale)
    base_size = float(player.size) * scale
    base_scale = base_size / cell

    draw_lan_player_ring(
        render_ctx,
        player=player,
        screen_pos=screen_pos,
        base_size=base_size,
        scale=scale,
        alpha=alpha,
    )

    if render_ctx.particles_texture is not None and perk_active(player, PerkId.RADIOACTIVE) and alpha > 1e-3:
        atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.AURA))
        if atlas is not None:
            aura_grid = SIZE_CODE_GRID.get(int(atlas.size_code))
            if aura_grid:
                frame = int(atlas.frame)
                col = frame % aura_grid
                row = frame // aura_grid
                cell_w = float(render_ctx.particles_texture.width) / float(aura_grid)
                cell_h = float(render_ctx.particles_texture.height) / float(aura_grid)
                src = rl.Rectangle(
                    cell_w * float(col),
                    cell_h * float(row),
                    max(0.0, cell_w - 2.0),
                    max(0.0, cell_h - 2.0),
                )
                t = float(render_ctx.elapsed_ms) * 0.001
                aura_alpha = ((math.sin(t) + 1.0) * 0.1875 + 0.25) * alpha
                if aura_alpha > 1e-3:
                    size = 100.0 * scale
                    dst = rl.Rectangle(screen_pos.x, screen_pos.y, float(size), float(size))
                    origin = rl.Vector2(size * 0.5, size * 0.5)
                    tint = rl.Color(77, 153, 77, int(clamp(aura_alpha, 0.0, 1.0) * 255.0 + 0.5))
                    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                    rl.draw_texture_pro(render_ctx.particles_texture, src, dst, origin, 0.0, tint)
                    rl.end_blend_mode()

    tint = rl.Color(240, 240, 255, int(255 * alpha + 0.5))
    shadow_tint = rl.Color(0, 0, 0, int(90 * alpha + 0.5))
    overlay_tint = tint
    if len(render_ctx.players) > 1:
        index = int(player.index)
        if index == 0:
            overlay_tint = rl.Color(77, 77, 255, tint.a)
        else:
            overlay_tint = rl.Color(255, 140, 89, tint.a)

    def draw(frame: int, *, pos: Vec2, scale_mul: float, rotation: float, color: rl.Color) -> None:
        render_ctx._draw_atlas_sprite(
            texture,
            grid=sprite_grid,
            frame=max(0, min(63, int(frame))),
            pos=pos,
            scale=base_scale * float(scale_mul),
            rotation_rad=float(rotation),
            tint=color,
        )

    if player.health > 0.0:
        leg_frame = max(0, min(14, int(player.move_phase + 0.5)))
        torso_frame = leg_frame + 16

        recoil_dir = float(player.aim_heading) + math.pi / 2.0
        recoil = float(player.muzzle_flash_alpha) * 12.0 * scale
        recoil_offset = Vec2.from_polar(recoil_dir, recoil)

        leg_shadow_scale = 1.02
        torso_shadow_scale = 1.03
        leg_shadow_off = 3.0 * scale + base_size * (leg_shadow_scale - 1.0) * 0.5
        torso_shadow_off = 1.0 * scale + base_size * (torso_shadow_scale - 1.0) * 0.5

        draw(
            leg_frame,
            pos=screen_pos.offset(dx=leg_shadow_off, dy=leg_shadow_off),
            scale_mul=leg_shadow_scale,
            rotation=float(player.heading),
            color=shadow_tint,
        )
        draw(
            torso_frame,
            pos=screen_pos.offset(dx=recoil_offset.x + torso_shadow_off, dy=recoil_offset.y + torso_shadow_off),
            scale_mul=torso_shadow_scale,
            rotation=float(player.aim_heading),
            color=shadow_tint,
        )

        draw(
            leg_frame,
            pos=screen_pos,
            scale_mul=1.0,
            rotation=float(player.heading),
            color=tint,
        )
        draw(
            torso_frame,
            pos=screen_pos + recoil_offset,
            scale_mul=1.0,
            rotation=float(player.aim_heading),
            color=overlay_tint,
        )

        if render_ctx.particles_texture is not None and float(player.shield_timer) > 1e-3 and alpha > 1e-3:
            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.SHIELD_RING))
            if atlas is not None:
                shield_grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                if shield_grid:
                    frame = int(atlas.frame)
                    col = frame % shield_grid
                    row = frame // shield_grid
                    cell_w = float(render_ctx.particles_texture.width) / float(shield_grid)
                    cell_h = float(render_ctx.particles_texture.height) / float(shield_grid)
                    src = rl.Rectangle(
                        cell_w * float(col),
                        cell_h * float(row),
                        max(0.0, cell_w - 2.0),
                        max(0.0, cell_h - 2.0),
                    )
                    t = float(render_ctx.elapsed_ms) * 0.001
                    timer = float(player.shield_timer)
                    strength = (math.sin(t) + 1.0) * 0.25 + timer
                    if timer < 1.0:
                        strength *= timer
                    strength = min(1.0, strength) * alpha
                    if strength > 1e-3:
                        offset_dir = float(player.aim_heading) - math.pi / 2.0
                        center = screen_pos + Vec2.from_polar(offset_dir, 3.0 * scale)

                        half = math.sin(t * 3.0) + 17.5
                        size = half * 2.0 * scale
                        a = int(clamp(strength * 0.4, 0.0, 1.0) * 255.0 + 0.5)
                        tint = rl.Color(91, 180, 255, a)
                        dst = rl.Rectangle(center.x, center.y, float(size), float(size))
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        rotation_deg = float((t + t) * _RAD_TO_DEG)

                        half = math.sin(t * 3.0) * 4.0 + 24.0
                        size2 = half * 2.0 * scale
                        a2 = int(clamp(strength * 0.3, 0.0, 1.0) * 255.0 + 0.5)
                        tint2 = rl.Color(91, 180, 255, a2)
                        dst2 = rl.Rectangle(center.x, center.y, float(size2), float(size2))
                        origin2 = rl.Vector2(size2 * 0.5, size2 * 0.5)
                        rotation2_deg = float((t * -2.0) * _RAD_TO_DEG)

                        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                        rl.draw_texture_pro(render_ctx.particles_texture, src, dst, origin, rotation_deg, tint)
                        rl.draw_texture_pro(render_ctx.particles_texture, src, dst2, origin2, rotation2_deg, tint2)
                        rl.end_blend_mode()

        if render_ctx.muzzle_flash_texture is not None and float(player.muzzle_flash_alpha) > 1e-3 and alpha > 1e-3:
            weapon = WEAPON_BY_ID.get(int(player.weapon.weapon_id))
            flags = int(weapon.flags) if weapon is not None and weapon.flags is not None else 0
            if (flags & 0x8) == 0:
                flash_alpha = clamp(float(player.muzzle_flash_alpha) * 0.8, 0.0, 1.0) * alpha
                if flash_alpha > 1e-3:
                    size = base_size * (0.5 if (flags & 0x4) else 1.0)
                    heading = float(player.aim_heading) + math.pi / 2.0
                    offset = (float(player.muzzle_flash_alpha) * 12.0 - 21.0) * scale
                    flash_pos = screen_pos + Vec2.from_angle(heading) * offset
                    src = rl.Rectangle(
                        0.0,
                        0.0,
                        float(render_ctx.muzzle_flash_texture.width),
                        float(render_ctx.muzzle_flash_texture.height),
                    )
                    dst = rl.Rectangle(flash_pos.x, flash_pos.y, size, size)
                    origin = rl.Vector2(size * 0.5, size * 0.5)
                    tint_flash = rl.Color(255, 255, 255, int(flash_alpha * 255.0 + 0.5))
                    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                    rl.draw_texture_pro(
                        render_ctx.muzzle_flash_texture,
                        src,
                        dst,
                        origin,
                        float(player.aim_heading * _RAD_TO_DEG),
                        tint_flash,
                    )
                    rl.end_blend_mode()
        return

    if player.death_timer >= 0.0:
        # Matches the observed frame ramp (32..52) in player_sprite_trace.jsonl.
        frame = 32 + int((16.0 - float(player.death_timer)) * 1.25)
        if frame > 52:
            frame = 52
        if frame < 32:
            frame = 32
    else:
        frame = 52

    dead_shadow_scale = 1.03
    dead_shadow_off = 1.0 * scale + base_size * (dead_shadow_scale - 1.0) * 0.5
    draw(
        frame,
        pos=screen_pos.offset(dx=dead_shadow_off, dy=dead_shadow_off),
        scale_mul=dead_shadow_scale,
        rotation=float(player.aim_heading),
        color=shadow_tint,
    )
    draw(frame, pos=screen_pos, scale_mul=1.0, rotation=float(player.aim_heading), color=overlay_tint)
