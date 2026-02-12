from __future__ import annotations

import math
from typing import TYPE_CHECKING

import pyray as rl

from grim.geom import Vec2
from grim.math import clamp

from ...creatures.anim import creature_anim_select_frame
from ...creatures.spawn import CreatureFlags, CreatureTypeId
from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from ...perks import PerkId
from ...perks.helpers import perk_active
from ...sim.world_defs import CREATURE_ANIM
from ...weapons import WEAPON_BY_ID
from .constants import _RAD_TO_DEG
from .mixin_base import WorldRendererMixinBase

if TYPE_CHECKING:
    from ...sim.state_types import PlayerState


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

    def _draw_player_trooper_sprite(
        self,
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

        screen_pos = self._world_to_screen_with(player.pos, camera=camera, view_scale=view_scale)
        base_size = float(player.size) * scale
        base_scale = base_size / cell

        if self.particles_texture is not None and perk_active(player, PerkId.RADIOACTIVE) and alpha > 1e-3:
            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.AURA))
            if atlas is not None:
                aura_grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                if aura_grid:
                    frame = int(atlas.frame)
                    col = frame % aura_grid
                    row = frame // aura_grid
                    cell_w = float(self.particles_texture.width) / float(aura_grid)
                    cell_h = float(self.particles_texture.height) / float(aura_grid)
                    src = rl.Rectangle(
                        cell_w * float(col),
                        cell_h * float(row),
                        max(0.0, cell_w - 2.0),
                        max(0.0, cell_h - 2.0),
                    )
                    t = float(self.elapsed_ms) * 0.001
                    aura_alpha = ((math.sin(t) + 1.0) * 0.1875 + 0.25) * alpha
                    if aura_alpha > 1e-3:
                        size = 100.0 * scale
                        dst = rl.Rectangle(screen_pos.x, screen_pos.y, float(size), float(size))
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(77, 153, 77, int(clamp(aura_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                        rl.draw_texture_pro(self.particles_texture, src, dst, origin, 0.0, tint)
                        rl.end_blend_mode()

        tint = rl.Color(240, 240, 255, int(255 * alpha + 0.5))
        shadow_tint = rl.Color(0, 0, 0, int(90 * alpha + 0.5))
        overlay_tint = tint
        if len(self.players) > 1:
            index = int(player.index)
            if index == 0:
                overlay_tint = rl.Color(77, 77, 255, tint.a)
            else:
                overlay_tint = rl.Color(255, 140, 89, tint.a)

        def draw(frame: int, *, pos: Vec2, scale_mul: float, rotation: float, color: rl.Color) -> None:
            self._draw_atlas_sprite(
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

            if self.particles_texture is not None and float(player.shield_timer) > 1e-3 and alpha > 1e-3:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.SHIELD_RING))
                if atlas is not None:
                    shield_grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if shield_grid:
                        frame = int(atlas.frame)
                        col = frame % shield_grid
                        row = frame // shield_grid
                        cell_w = float(self.particles_texture.width) / float(shield_grid)
                        cell_h = float(self.particles_texture.height) / float(shield_grid)
                        src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )
                        t = float(self.elapsed_ms) * 0.001
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
                                rl.draw_texture_pro(self.particles_texture, src, dst, origin, rotation_deg, tint)
                                rl.draw_texture_pro(self.particles_texture, src, dst2, origin2, rotation2_deg, tint2)
                                rl.end_blend_mode()

            if self.muzzle_flash_texture is not None and float(player.muzzle_flash_alpha) > 1e-3 and alpha > 1e-3:
                weapon = WEAPON_BY_ID.get(int(player.weapon_id))
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
                            float(self.muzzle_flash_texture.width),
                            float(self.muzzle_flash_texture.height),
                        )
                        dst = rl.Rectangle(flash_pos.x, flash_pos.y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint_flash = rl.Color(255, 255, 255, int(flash_alpha * 255.0 + 0.5))
                        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                        rl.draw_texture_pro(
                            self.muzzle_flash_texture,
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
