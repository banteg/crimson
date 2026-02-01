from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING

import pyray as rl

from grim.math import clamp
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.terrain_render import _maybe_alpha_test

from ..bonuses import BONUS_BY_ID, BonusId
from ..creatures.anim import creature_anim_select_frame
from ..creatures.spawn import CreatureFlags, CreatureTypeId
from ..effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID
from ..gameplay import bonus_find_aim_hover_entry, perk_active
from ..perks import PerkId
from ..projectiles import ProjectileTypeId
from ..sim.world_defs import (
    BEAM_TYPES,
    CREATURE_ANIM,
    CREATURE_ASSET,
    ION_TYPES,
    KNOWN_PROJ_FRAMES,
    PLASMA_PARTICLE_TYPES,
)
from ..weapons import WEAPON_BY_ID

if TYPE_CHECKING:
    from ..game_world import GameWorld

_RAD_TO_DEG = 57.29577951308232


def monster_vision_fade_alpha(hitbox_size: float) -> float:
    if float(hitbox_size) >= 0.0:
        return 1.0
    return clamp((float(hitbox_size) + 10.0) * 0.1, 0.0, 1.0)


@dataclass(slots=True)
class WorldRenderer:
    _world: GameWorld
    _small_font: SmallFontData | None = None

    def __getattr__(self, name: str) -> object:
        return getattr(self._world, name)

    def _ensure_small_font(self) -> SmallFontData | None:
        if self._small_font is not None:
            return self._small_font
        try:
            # Keep UI text consistent with the HUD/menu font when available.
            self._small_font = load_small_font(self.assets_dir, self.missing_assets)
        except Exception:
            self._small_font = None
        return self._small_font

    def _camera_screen_size(self) -> tuple[float, float]:
        if self.config is not None:
            screen_w = float(self.config.screen_width)
            screen_h = float(self.config.screen_height)
        else:
            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
        if screen_w > self.world_size:
            screen_w = float(self.world_size)
        if screen_h > self.world_size:
            screen_h = float(self.world_size)
        return screen_w, screen_h

    def _clamp_camera(self, cam_x: float, cam_y: float, screen_w: float, screen_h: float) -> tuple[float, float]:
        min_x = screen_w - float(self.world_size)
        min_y = screen_h - float(self.world_size)
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_x < min_x:
            cam_x = min_x
        if cam_y > -1.0:
            cam_y = -1.0
        if cam_y < min_y:
            cam_y = min_y
        return cam_x, cam_y

    def _world_params(self) -> tuple[float, float, float, float]:
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w, screen_h = self._camera_screen_size()
        cam_x, cam_y = self._clamp_camera(self.camera_x, self.camera_y, screen_w, screen_h)
        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        return cam_x, cam_y, scale_x, scale_y

    def _color_from_rgba(self, rgba: tuple[float, float, float, float]) -> rl.Color:
        r = int(clamp(rgba[0], 0.0, 1.0) * 255.0 + 0.5)
        g = int(clamp(rgba[1], 0.0, 1.0) * 255.0 + 0.5)
        b = int(clamp(rgba[2], 0.0, 1.0) * 255.0 + 0.5)
        a = int(clamp(rgba[3], 0.0, 1.0) * 255.0 + 0.5)
        return rl.Color(r, g, b, a)

    def _bonus_icon_src(self, texture: rl.Texture, icon_id: int) -> rl.Rectangle:
        grid = 4
        cell_w = float(texture.width) / grid
        cell_h = float(texture.height) / grid
        col = int(icon_id) % grid
        row = int(icon_id) // grid
        return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w), float(cell_h))

    def _weapon_icon_src(self, texture: rl.Texture, icon_index: int) -> rl.Rectangle:
        grid = 8
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        frame = int(icon_index) * 2
        col = frame % grid
        row = frame // grid
        return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w * 2), float(cell_h))

    @staticmethod
    def _bonus_fade(time_left: float, time_max: float) -> float:
        time_left = float(time_left)
        time_max = float(time_max)
        if time_left <= 0.0 or time_max <= 0.0:
            return 0.0
        if time_left < 0.5:
            return clamp(time_left * 2.0, 0.0, 1.0)
        age = time_max - time_left
        if age < 0.5:
            return clamp(age * 2.0, 0.0, 1.0)
        return 1.0

    def _draw_bonus_pickups(
        self,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        scale: float,
        alpha: float = 1.0,
    ) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        if self.bonuses_texture is None:
            for bonus in self.state.bonus_pool.entries:
                if bonus.bonus_id == 0:
                    continue
                sx = (bonus.pos_x + cam_x) * scale_x
                sy = (bonus.pos_y + cam_y) * scale_y
                tint = rl.Color(220, 220, 90, int(255 * alpha + 0.5))
                rl.draw_circle(int(sx), int(sy), max(1.0, 10.0 * scale), tint)
            return

        bubble_src = self._bonus_icon_src(self.bonuses_texture, 0)
        bubble_size = 32.0 * scale

        for idx, bonus in enumerate(self.state.bonus_pool.entries):
            if bonus.bonus_id == 0:
                continue

            fade = self._bonus_fade(float(bonus.time_left), float(bonus.time_max))
            bubble_alpha = clamp(fade * 0.9, 0.0, 1.0) * alpha

            sx = (bonus.pos_x + cam_x) * scale_x
            sy = (bonus.pos_y + cam_y) * scale_y
            bubble_dst = rl.Rectangle(float(sx), float(sy), float(bubble_size), float(bubble_size))
            bubble_origin = rl.Vector2(bubble_size * 0.5, bubble_size * 0.5)
            tint = rl.Color(255, 255, 255, int(bubble_alpha * 255.0 + 0.5))
            rl.draw_texture_pro(self.bonuses_texture, bubble_src, bubble_dst, bubble_origin, 0.0, tint)

            bonus_id = int(bonus.bonus_id)
            if bonus_id == int(BonusId.WEAPON):
                weapon = WEAPON_BY_ID.get(int(bonus.amount))
                icon_index = int(weapon.icon_index) if weapon is not None and weapon.icon_index is not None else None
                if icon_index is None or not (0 <= icon_index <= 31) or self.wicons_texture is None:
                    continue

                pulse = math.sin(float(self._bonus_anim_phase)) ** 4 * 0.25 + 0.75
                icon_scale = fade * pulse
                if icon_scale <= 1e-3:
                    continue

                src = self._weapon_icon_src(self.wicons_texture, icon_index)
                w = 60.0 * icon_scale * scale
                h = 30.0 * icon_scale * scale
                dst = rl.Rectangle(float(sx), float(sy), float(w), float(h))
                origin = rl.Vector2(w * 0.5, h * 0.5)
                rl.draw_texture_pro(self.wicons_texture, src, dst, origin, 0.0, tint)
                continue

            meta = BONUS_BY_ID.get(bonus_id)
            icon_id = int(meta.icon_id) if meta is not None and meta.icon_id is not None else None
            if icon_id is None or icon_id < 0:
                continue
            if bonus_id == int(BonusId.POINTS) and int(bonus.amount) == 1000:
                icon_id += 1

            pulse = math.sin(float(idx) + float(self._bonus_anim_phase)) ** 4 * 0.25 + 0.75
            icon_scale = fade * pulse
            if icon_scale <= 1e-3:
                continue

            src = self._bonus_icon_src(self.bonuses_texture, icon_id)
            size = 32.0 * icon_scale * scale
            rotation_rad = math.sin(float(idx) - float(self._elapsed_ms) * 0.003) * 0.2
            dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rl.draw_texture_pro(self.bonuses_texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), tint)

    def _bonus_hover_label(self, bonus_id: int, amount: int) -> str:
        bonus_id = int(bonus_id)
        if bonus_id == int(BonusId.WEAPON):
            weapon = WEAPON_BY_ID.get(int(amount))
            if weapon is not None and weapon.name is not None:
                return str(weapon.name)
            return "Weapon"
        if bonus_id == int(BonusId.POINTS):
            return f"Score: {int(amount)}"
        meta = BONUS_BY_ID.get(int(bonus_id))
        if meta is not None:
            return str(meta.name)
        return "Bonus"

    def _draw_bonus_hover_labels(
        self,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        alpha: float = 1.0,
    ) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return

        font = self._ensure_small_font()
        text_scale = 1.0
        screen_w = float(rl.get_screen_width())

        shadow = rl.Color(0, 0, 0, int(180 * alpha + 0.5))
        color = rl.Color(230, 230, 230, int(255 * alpha + 0.5))

        for player in self.players:
            if player.health <= 0.0:
                continue
            hovered = bonus_find_aim_hover_entry(player, self.state.bonus_pool)
            if hovered is None:
                continue
            _idx, entry = hovered
            label = self._bonus_hover_label(int(entry.bonus_id), int(entry.amount))
            if not label:
                continue

            aim_x = float(getattr(player, "aim_x", player.pos_x))
            aim_y = float(getattr(player, "aim_y", player.pos_y))
            x = (aim_x + cam_x) * scale_x + 16.0
            y = (aim_y + cam_y) * scale_y - 7.0

            if font is not None:
                text_w = measure_small_text_width(font, label, text_scale)
            else:
                text_w = float(rl.measure_text(label, int(18 * text_scale)))
            if x + text_w > screen_w:
                x = max(0.0, screen_w - text_w)

            if font is not None:
                draw_small_text(font, label, x + 1.0, y + 1.0, text_scale, shadow)
                draw_small_text(font, label, x, y, text_scale, color)
            else:
                rl.draw_text(label, int(x) + 1, int(y) + 1, int(18 * text_scale), shadow)
                rl.draw_text(label, int(x), int(y), int(18 * text_scale), color)

    def _draw_atlas_sprite(
        self,
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        x: float,
        y: float,
        scale: float,
        rotation_rad: float = 0.0,
        tint: rl.Color = rl.WHITE,
    ) -> None:
        grid = max(1, int(grid))
        frame = max(0, int(frame))
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        col = frame % grid
        row = frame // grid
        src = rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)
        w = cell_w * float(scale)
        h = cell_h * float(scale)
        dst = rl.Rectangle(float(x), float(y), w, h)
        origin = rl.Vector2(w * 0.5, h * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), tint)

    @staticmethod
    def _grim2d_circle_segments_filled(radius: float) -> int:
        # grim_draw_circle_filled (grim.dll): segments = trunc(radius * 0.125 + 12.0)
        return max(3, int(radius * 0.125 + 12.0))

    @staticmethod
    def _grim2d_circle_segments_outline(radius: float) -> int:
        # grim_draw_circle_outline (grim.dll): segments = trunc(radius * 0.2 + 14.0)
        return max(3, int(radius * 0.2 + 14.0))

    def _draw_aim_circle(self, *, x: float, y: float, radius: float, alpha: float = 1.0) -> None:
        if radius <= 1e-3:
            return
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return

        fill_a = int(77 * alpha + 0.5)  # ui_render_aim_indicators: rgba(0,0,0.1,0.3)
        outline_a = int(255 * 0.55 * alpha + 0.5)
        fill = rl.Color(0, 0, 26, fill_a)
        outline = rl.Color(255, 255, 255, outline_a)

        rl.begin_blend_mode(rl.BLEND_ALPHA)

        # The original uses a triangle fan (polygons). Raylib provides circle
        # primitives that still use triangles internally, but allow higher
        # segment counts for a smoother result when scaled.
        seg_count = max(self._grim2d_circle_segments_filled(radius), 64, int(radius))
        rl.draw_circle_sector(rl.Vector2(x, y), float(radius), 0.0, 360.0, int(seg_count), fill)

        seg_count = max(self._grim2d_circle_segments_outline(radius), int(seg_count))
        # grim_draw_circle_outline draws a 2px-thick ring (outer radius = r + 2).
        # The exe binds bulletTrail, but that texture is white; the visual intent is
        # a subtle white outline around the filled spread circle.
        rl.draw_ring(rl.Vector2(x, y), float(radius), float(radius + 2.0), 0.0, 360.0, int(seg_count), outline)

        rl.rl_set_texture(0)
        rl.end_blend_mode()

    def _draw_clock_gauge(self, *, x: float, y: float, ms: int, scale: float, alpha: float = 1.0) -> None:
        if self.clock_table_texture is None or self.clock_pointer_texture is None:
            return
        size = 32.0 * scale
        if size <= 1e-3:
            return
        tint = rl.Color(255, 255, 255, int(clamp(float(alpha), 0.0, 1.0) * 255.0 + 0.5))
        half = size * 0.5

        table_src = rl.Rectangle(0.0, 0.0, float(self.clock_table_texture.width), float(self.clock_table_texture.height))
        table_dst = rl.Rectangle(float(x), float(y), size, size)
        rl.draw_texture_pro(self.clock_table_texture, table_src, table_dst, rl.Vector2(0.0, 0.0), 0.0, tint)

        seconds = int(ms) // 1000
        pointer_src = rl.Rectangle(
            0.0,
            0.0,
            float(self.clock_pointer_texture.width),
            float(self.clock_pointer_texture.height),
        )
        pointer_dst = rl.Rectangle(float(x) + half, float(y) + half, size, size)
        origin = rl.Vector2(half, half)
        rotation_deg = float(seconds) * 6.0
        rl.draw_texture_pro(self.clock_pointer_texture, pointer_src, pointer_dst, origin, rotation_deg, tint)

    def _draw_creature_sprite(
        self,
        texture: rl.Texture,
        *,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        mirror_long: bool | None = None,
        shadow_alpha: int | None = None,
        world_x: float,
        world_y: float,
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

        sx, sy = self.world_to_screen(world_x, world_y)
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
            shadow_dst = rl.Rectangle(sx + offset, sy + offset, shadow_w, shadow_h)
            shadow_origin = rl.Vector2(shadow_w * 0.5, shadow_h * 0.5)
            rl.draw_texture_pro(texture, src, shadow_dst, shadow_origin, rotation_deg, shadow_tint)

        dst = rl.Rectangle(sx, sy, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    def _draw_player_trooper_sprite(
        self,
        texture: rl.Texture,
        player: object,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        scale: float,
        alpha: float = 1.0,
    ) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        grid = 8
        cell = float(texture.width) / float(grid) if grid > 0 else float(texture.width)
        if cell <= 0.0:
            return

        sx = (player.pos_x + cam_x) * scale_x
        sy = (player.pos_y + cam_y) * scale_y
        base_size = float(player.size) * scale
        base_scale = base_size / cell

        if (
            self.particles_texture is not None
            and perk_active(player, PerkId.RADIOACTIVE)
            and alpha > 1e-3
        ):
            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x10)
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
                    t = float(self._elapsed_ms) * 0.001
                    aura_alpha = ((math.sin(t) + 1.0) * 0.1875 + 0.25) * alpha
                    if aura_alpha > 1e-3:
                        size = 100.0 * scale
                        dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(77, 153, 77, int(clamp(aura_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                        rl.draw_texture_pro(self.particles_texture, src, dst, origin, 0.0, tint)
                        rl.end_blend_mode()

        tint = rl.Color(240, 240, 255, int(255 * alpha + 0.5))
        shadow_tint = rl.Color(0, 0, 0, int(90 * alpha + 0.5))
        overlay_tint = tint
        if len(self.players) > 1:
            index = int(getattr(player, "index", 0))
            if index == 0:
                overlay_tint = rl.Color(77, 77, 255, tint.a)
            else:
                overlay_tint = rl.Color(255, 140, 89, tint.a)

        def draw(frame: int, *, x: float, y: float, scale_mul: float, rotation: float, color: rl.Color) -> None:
            self._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=max(0, min(63, int(frame))),
                x=x,
                y=y,
                scale=base_scale * float(scale_mul),
                rotation_rad=float(rotation),
                tint=color,
            )

        if player.health > 0.0:
            leg_frame = max(0, min(14, int(player.move_phase + 0.5)))
            torso_frame = leg_frame + 16

            recoil_dir = float(player.aim_heading) + math.pi / 2.0
            recoil = float(player.muzzle_flash_alpha) * 12.0 * scale
            recoil_x = math.cos(recoil_dir) * recoil
            recoil_y = math.sin(recoil_dir) * recoil

            leg_shadow_scale = 1.02
            torso_shadow_scale = 1.03
            leg_shadow_off = 3.0 * scale + base_size * (leg_shadow_scale - 1.0) * 0.5
            torso_shadow_off = 1.0 * scale + base_size * (torso_shadow_scale - 1.0) * 0.5

            draw(
                leg_frame,
                x=sx + leg_shadow_off,
                y=sy + leg_shadow_off,
                scale_mul=leg_shadow_scale,
                rotation=float(player.heading),
                color=shadow_tint,
            )
            draw(
                torso_frame,
                x=sx + recoil_x + torso_shadow_off,
                y=sy + recoil_y + torso_shadow_off,
                scale_mul=torso_shadow_scale,
                rotation=float(player.aim_heading),
                color=shadow_tint,
            )

            draw(
                leg_frame,
                x=sx,
                y=sy,
                scale_mul=1.0,
                rotation=float(player.heading),
                color=tint,
            )
            draw(
                torso_frame,
                x=sx + recoil_x,
                y=sy + recoil_y,
                scale_mul=1.0,
                rotation=float(player.aim_heading),
                color=overlay_tint,
            )

            if self.particles_texture is not None and float(player.shield_timer) > 1e-3 and alpha > 1e-3:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x02)
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        cell_w = float(self.particles_texture.width) / float(grid)
                        cell_h = float(self.particles_texture.height) / float(grid)
                        src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )
                        t = float(self._elapsed_ms) * 0.001
                        timer = float(player.shield_timer)
                        strength = (math.sin(t) + 1.0) * 0.25 + timer
                        if timer < 1.0:
                            strength *= timer
                        strength = min(1.0, strength) * alpha
                        if strength > 1e-3:
                            offset_dir = float(player.aim_heading) - math.pi / 2.0
                            ox = math.cos(offset_dir) * 3.0 * scale
                            oy = math.sin(offset_dir) * 3.0 * scale
                            cx = sx + ox
                            cy = sy + oy

                            half = math.sin(t * 3.0) + 17.5
                            size = half * 2.0 * scale
                            a = int(clamp(strength * 0.4, 0.0, 1.0) * 255.0 + 0.5)
                            tint = rl.Color(91, 180, 255, a)
                            dst = rl.Rectangle(float(cx), float(cy), float(size), float(size))
                            origin = rl.Vector2(size * 0.5, size * 0.5)
                            rotation_deg = float((t + t) * _RAD_TO_DEG)

                            half = math.sin(t * 3.0) * 4.0 + 24.0
                            size2 = half * 2.0 * scale
                            a2 = int(clamp(strength * 0.3, 0.0, 1.0) * 255.0 + 0.5)
                            tint2 = rl.Color(91, 180, 255, a2)
                            dst2 = rl.Rectangle(float(cx), float(cy), float(size2), float(size2))
                            origin2 = rl.Vector2(size2 * 0.5, size2 * 0.5)
                            rotation2_deg = float((t * -2.0) * _RAD_TO_DEG)

                            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
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
                        pos_x = sx + math.cos(heading) * offset
                        pos_y = sy + math.sin(heading) * offset
                        src = rl.Rectangle(
                            0.0,
                            0.0,
                            float(self.muzzle_flash_texture.width),
                            float(self.muzzle_flash_texture.height),
                        )
                        dst = rl.Rectangle(pos_x, pos_y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint_flash = rl.Color(255, 255, 255, int(flash_alpha * 255.0 + 0.5))
                        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
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
            x=sx + dead_shadow_off,
            y=sy + dead_shadow_off,
            scale_mul=dead_shadow_scale,
            rotation=float(player.aim_heading),
            color=shadow_tint,
        )
        draw(frame, x=sx, y=sy, scale_mul=1.0, rotation=float(player.aim_heading), color=overlay_tint)

    def _draw_projectile(self, proj: object, *, proj_index: int = 0, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.projs_texture
        type_id = int(getattr(proj, "type_id", 0))
        pos_x = float(getattr(proj, "pos_x", 0.0))
        pos_y = float(getattr(proj, "pos_y", 0.0))
        sx, sy = self.world_to_screen(pos_x, pos_y)
        life = float(getattr(proj, "life_timer", 0.0))
        angle = float(getattr(proj, "angle", 0.0))

        if self._is_bullet_trail_type(type_id):
            life_alpha = int(clamp(life, 0.0, 1.0) * 255)
            alpha_byte = int(clamp(float(life_alpha) * alpha, 0.0, 255.0) + 0.5)
            drawn = False
            if self.bullet_trail_texture is not None:
                ox = float(getattr(proj, "origin_x", pos_x))
                oy = float(getattr(proj, "origin_y", pos_y))
                sx0, sy0 = self.world_to_screen(ox, oy)
                sx1, sy1 = sx, sy
                drawn = self._draw_bullet_trail(sx0, sy0, sx1, sy1, type_id=type_id, alpha=alpha_byte, scale=scale)

            if self.bullet_texture is not None and life >= 0.39:
                size = self._bullet_sprite_size(type_id, scale=scale)
                src = rl.Rectangle(
                    0.0,
                    0.0,
                    float(self.bullet_texture.width),
                    float(self.bullet_texture.height),
                )
                dst = rl.Rectangle(float(sx), float(sy), size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                tint = rl.Color(220, 220, 220, alpha_byte)
                rl.draw_texture_pro(self.bullet_texture, src, dst, origin, float(angle * _RAD_TO_DEG), tint)
                drawn = True

            if drawn:
                return

        if type_id in PLASMA_PARTICLE_TYPES and self.particles_texture is not None:
            particles_texture = self.particles_texture
            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x0D)
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

                    speed_scale = float(getattr(proj, "speed_scale", 1.0))
                    fx_detail_1 = bool(self.config.data.get("fx_detail_1", 0)) if self.config is not None else True

                    rgb = (1.0, 1.0, 1.0)
                    spacing = 2.1
                    seg_limit = 3
                    tail_size = 12.0
                    head_size = 16.0
                    head_alpha_mul = 0.45
                    aura_rgb = rgb
                    aura_size = 120.0
                    aura_alpha_mul = 0.15

                    if type_id == int(ProjectileTypeId.PLASMA_RIFLE):
                        spacing = 2.5
                        seg_limit = 8
                        tail_size = 22.0
                        head_size = 56.0
                        aura_size = 256.0
                        aura_alpha_mul = 0.3
                    elif type_id == int(ProjectileTypeId.PLASMA_MINIGUN):
                        spacing = 2.1
                        seg_limit = 3
                        tail_size = 12.0
                        head_size = 16.0
                        aura_size = 120.0
                        aura_alpha_mul = 0.15
                    elif type_id == int(ProjectileTypeId.PLASMA_CANNON):
                        spacing = 2.6
                        seg_limit = 18
                        tail_size = 44.0
                        head_size = 84.0
                        aura_size = 256.0
                        # In the decompile, cannon reuses the tail alpha for the aura (0.4).
                        aura_alpha_mul = 0.4
                    elif type_id == int(ProjectileTypeId.SPIDER_PLASMA):
                        rgb = (0.3, 1.0, 0.3)
                        aura_rgb = rgb
                    elif type_id == int(ProjectileTypeId.SHRINKIFIER):
                        rgb = (0.3, 0.3, 1.0)
                        aura_rgb = rgb

                    if life >= 0.4:
                        # Reconstruct the tail length heuristic used by the native render path.
                        seg_count = int(float(getattr(proj, "base_damage", 0.0)))
                        if seg_count < 0:
                            seg_count = 0
                        seg_count //= 5
                        if seg_count > seg_limit:
                            seg_count = seg_limit

                        # The stored projectile angle is rotated by +pi/2 vs travel direction.
                        dir_x = math.cos(angle + math.pi / 2.0) * speed_scale
                        dir_y = math.sin(angle + math.pi / 2.0) * speed_scale

                        tail_tint = self._color_from_rgba((rgb[0], rgb[1], rgb[2], alpha * 0.4))
                        head_tint = self._color_from_rgba((rgb[0], rgb[1], rgb[2], alpha * head_alpha_mul))
                        aura_tint = self._color_from_rgba((aura_rgb[0], aura_rgb[1], aura_rgb[2], alpha * aura_alpha_mul))

                        rl.begin_blend_mode(rl.BLEND_ADDITIVE)

                        if seg_count > 0:
                            size = tail_size * scale
                            origin = rl.Vector2(size * 0.5, size * 0.5)
                            step_x = dir_x * spacing
                            step_y = dir_y * spacing
                            for idx in range(seg_count):
                                px = pos_x + float(idx) * step_x
                                py = pos_y + float(idx) * step_y
                                psx, psy = self.world_to_screen(px, py)
                                dst = rl.Rectangle(float(psx), float(psy), float(size), float(size))
                                rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tail_tint)

                        size = head_size * scale
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, head_tint)

                        if fx_detail_1:
                            size = aura_size * scale
                            origin = rl.Vector2(size * 0.5, size * 0.5)
                            dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                            rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, aura_tint)

                        rl.end_blend_mode()
                        return

                    fade = clamp(life * 2.5, 0.0, 1.0)
                    fade_alpha = fade * alpha
                    if fade_alpha > 1e-3:
                        tint = self._color_from_rgba((1.0, 1.0, 1.0, fade_alpha))
                        size = 56.0 * scale
                        dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)
                        rl.end_blend_mode()
                    return

        if type_id in BEAM_TYPES and texture is not None:
            # Ion weapons and Fire Bullets use the projs.png streak effect (and Ion adds chain arcs on impact).
            grid = 4
            frame = 2

            is_fire_bullets = type_id == int(ProjectileTypeId.FIRE_BULLETS)
            is_ion = type_id in ION_TYPES

            ox = float(getattr(proj, "origin_x", pos_x))
            oy = float(getattr(proj, "origin_y", pos_y))
            dx = pos_x - ox
            dy = pos_y - oy
            dist = math.hypot(dx, dy)
            if dist <= 1e-6:
                return

            dir_x = dx / dist
            dir_y = dy / dist

            # In the native renderer, Ion Gun Master increases the chain effect thickness and reach.
            perk_scale = 1.0
            if any(perk_active(player, PerkId.ION_GUN_MASTER) for player in self.players):
                perk_scale = 1.2

            if type_id == int(ProjectileTypeId.ION_MINIGUN):
                effect_scale = 1.05
            elif type_id == int(ProjectileTypeId.ION_RIFLE):
                effect_scale = 2.2
            elif type_id == int(ProjectileTypeId.ION_CANNON):
                effect_scale = 3.5
            else:
                effect_scale = 0.8

            if life >= 0.4:
                base_alpha = alpha
            else:
                fade = clamp(life * 2.5, 0.0, 1.0)
                base_alpha = fade * alpha

            if base_alpha <= 1e-3:
                return

            streak_rgb = (1.0, 0.6, 0.1) if is_fire_bullets else (0.5, 0.6, 1.0)
            head_rgb = (1.0, 1.0, 0.7)

            # Only draw the last 256 units of the path.
            start = 0.0
            span = dist
            if dist > 256.0:
                start = dist - 256.0
                span = 256.0

            step = min(effect_scale * 3.1, 9.0)
            sprite_scale = effect_scale * scale

            rl.begin_blend_mode(rl.BLEND_ADDITIVE)

            s = start
            while s < dist:
                t = (s - start) / span if span > 1e-6 else 1.0
                seg_alpha = t * base_alpha
                if seg_alpha > 1e-3:
                    px = ox + dir_x * s
                    py = oy + dir_y * s
                    psx, psy = self.world_to_screen(px, py)
                    tint = self._color_from_rgba((streak_rgb[0], streak_rgb[1], streak_rgb[2], seg_alpha))
                    self._draw_atlas_sprite(
                        texture,
                        grid=grid,
                        frame=frame,
                        x=psx,
                        y=psy,
                        scale=sprite_scale,
                        rotation_rad=angle,
                        tint=tint,
                    )
                s += step

            if life >= 0.4:
                head_tint = self._color_from_rgba((head_rgb[0], head_rgb[1], head_rgb[2], base_alpha))
                self._draw_atlas_sprite(
                    texture,
                    grid=grid,
                    frame=frame,
                    x=sx,
                    y=sy,
                    scale=sprite_scale,
                    rotation_rad=angle,
                    tint=head_tint,
                )

                # Fire Bullets renders an extra particles.png overlay in a later pass.
                if is_fire_bullets and self.particles_texture is not None:
                    particles_texture = self.particles_texture
                    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x0D)
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
                            tint = self._color_from_rgba((1.0, 1.0, 1.0, alpha))
                            size = 64.0 * scale
                            dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                            origin = rl.Vector2(size * 0.5, size * 0.5)
                            rl.draw_texture_pro(particles_texture, src, dst, origin, float(angle * _RAD_TO_DEG), tint)
            else:
                # Native draws a small blue "core" at the head during the fade stage (life_timer < 0.4).
                core_tint = self._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
                self._draw_atlas_sprite(
                    texture,
                    grid=grid,
                    frame=frame,
                    x=sx,
                    y=sy,
                    scale=1.0 * scale,
                    rotation_rad=angle,
                    tint=core_tint,
                )

                if is_ion:
                    # Native: chain reach is derived from the streak scale (`fVar29 * perk_scale * 40.0`).
                    radius = effect_scale * perk_scale * 40.0

                    # Pick a stable set of targets so the arc visuals don't flicker.
                    candidates: list[tuple[float, object]] = []
                    for creature in self.creatures.entries:
                        if not creature.active or float(creature.hp) <= 0.0:
                            continue
                        if float(getattr(creature, "hitbox_size", 0.0)) < 5.0:
                            continue
                        d = math.hypot(float(creature.x) - pos_x, float(creature.y) - pos_y)
                        threshold = float(creature.size) * 0.142857149 + 3.0
                        if d > radius + threshold:
                            continue
                        candidates.append((d, creature))

                    candidates.sort(key=lambda item: item[0])
                    targets = [creature for _d, creature in candidates[:8]]

                    inner_half = 10.0 * perk_scale * scale
                    outer_half = 14.0 * perk_scale * scale
                    u = 0.625
                    v0 = 0.0
                    v1 = 0.25

                    glow_targets: list[object] = []
                    rl.rl_set_texture(texture.id)
                    rl.rl_begin(rl.RL_QUADS)

                    for creature in targets:
                        tx, ty = self.world_to_screen(float(creature.x), float(creature.y))
                        ddx = tx - sx
                        ddy = ty - sy
                        dlen = math.hypot(ddx, ddy)
                        if dlen <= 1e-3:
                            continue
                        glow_targets.append(creature)
                        inv = 1.0 / dlen
                        nx = ddx * inv
                        ny = ddy * inv
                        px = -ny
                        py = nx

                        # Outer strip (softer).
                        half = outer_half
                        off_x = px * half
                        off_y = py * half
                        x0 = sx - off_x
                        y0 = sy - off_y
                        x1 = sx + off_x
                        y1 = sy + off_y
                        x2 = tx + off_x
                        y2 = ty + off_y
                        x3 = tx - off_x
                        y3 = ty - off_y

                        outer_tint = self._color_from_rgba((0.5, 0.6, 1.0, base_alpha * 0.5))
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
                        off_x = px * half
                        off_y = py * half
                        x0 = sx - off_x
                        y0 = sy - off_y
                        x1 = sx + off_x
                        y1 = sy + off_y
                        x2 = tx + off_x
                        y2 = ty + off_y
                        x3 = tx - off_x
                        y3 = ty - off_y

                        inner_tint = self._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
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
                        tx, ty = self.world_to_screen(float(creature.x), float(creature.y))
                        target_tint = self._color_from_rgba((0.5, 0.6, 1.0, base_alpha))
                        self._draw_atlas_sprite(
                            texture,
                            grid=grid,
                            frame=frame,
                            x=tx,
                            y=ty,
                            scale=sprite_scale,
                            rotation_rad=0.0,
                            tint=target_tint,
                        )

            rl.end_blend_mode()
            return

        if type_id == int(ProjectileTypeId.PULSE_GUN) and texture is not None:
            mapping = KNOWN_PROJ_FRAMES.get(type_id)
            if mapping is None:
                return
            grid, frame = mapping
            cell_w = float(texture.width) / float(grid)

            if life >= 0.4:
                ox = float(getattr(proj, "origin_x", pos_x))
                oy = float(getattr(proj, "origin_y", pos_y))
                dist = math.hypot(pos_x - ox, pos_y - oy)

                desired_size = dist * 0.16 * scale
                if desired_size <= 1e-3:
                    return
                sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
                if sprite_scale <= 1e-6:
                    return

                tint = self._color_from_rgba((0.1, 0.6, 0.2, alpha * 0.7))
                rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                self._draw_atlas_sprite(
                    texture,
                    grid=grid,
                    frame=frame,
                    x=sx,
                    y=sy,
                    scale=sprite_scale,
                    rotation_rad=angle,
                    tint=tint,
                )
                rl.end_blend_mode()
                return

            fade = clamp(life * 2.5, 0.0, 1.0)
            fade_alpha = fade * alpha
            if fade_alpha <= 1e-3:
                return

            desired_size = 56.0 * scale
            sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
            if sprite_scale <= 1e-6:
                return

            tint = self._color_from_rgba((1.0, 1.0, 1.0, fade_alpha))
            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
            self._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                x=sx,
                y=sy,
                scale=sprite_scale,
                rotation_rad=angle,
                tint=tint,
            )
            rl.end_blend_mode()
            return

        if type_id in (int(ProjectileTypeId.SPLITTER_GUN), int(ProjectileTypeId.BLADE_GUN)) and texture is not None:
            mapping = KNOWN_PROJ_FRAMES.get(type_id)
            if mapping is None:
                return
            grid, frame = mapping
            cell_w = float(texture.width) / float(grid)

            if life < 0.4:
                return

            ox = float(getattr(proj, "origin_x", pos_x))
            oy = float(getattr(proj, "origin_y", pos_y))
            dist = math.hypot(pos_x - ox, pos_y - oy)

            desired_size = min(dist, 20.0) * scale
            if desired_size <= 1e-3:
                return

            sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
            if sprite_scale <= 1e-6:
                return

            rotation_rad = angle
            rgb = (1.0, 1.0, 1.0)
            if type_id == int(ProjectileTypeId.BLADE_GUN):
                rotation_rad = float(int(proj_index)) * 0.1 - float(self._elapsed_ms) * 0.1
                rgb = (0.8, 0.8, 0.8)

            tint = self._color_from_rgba((rgb[0], rgb[1], rgb[2], alpha))
            self._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                x=sx,
                y=sy,
                scale=sprite_scale,
                rotation_rad=rotation_rad,
                tint=tint,
            )
            return

        if type_id == int(ProjectileTypeId.PLAGUE_SPREADER) and texture is not None:
            grid = 4
            frame = 2
            cell_w = float(texture.width) / float(grid)

            if life >= 0.4:
                tint = self._color_from_rgba((1.0, 1.0, 1.0, alpha))

                def draw_plague_quad(*, px: float, py: float, size: float) -> None:
                    size = float(size)
                    if size <= 1e-3:
                        return
                    desired_size = size * scale
                    sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
                    if sprite_scale <= 1e-6:
                        return
                    psx, psy = self.world_to_screen(px, py)
                    self._draw_atlas_sprite(
                        texture,
                        grid=grid,
                        frame=frame,
                        x=psx,
                        y=psy,
                        scale=sprite_scale,
                        rotation_rad=0.0,
                        tint=tint,
                    )

                draw_plague_quad(px=pos_x, py=pos_y, size=60.0)

                offset_angle = angle + math.pi / 2.0
                draw_plague_quad(
                    px=pos_x + math.cos(offset_angle) * 15.0,
                    py=pos_y + math.sin(offset_angle) * 15.0,
                    size=60.0,
                )

                phase = float(int(proj_index)) + float(self._elapsed_ms) * 0.01
                cos_phase = math.cos(phase)
                sin_phase = math.sin(phase)
                draw_plague_quad(
                    px=pos_x + cos_phase * cos_phase - 5.0,
                    py=pos_y + sin_phase * 11.0 - 5.0,
                    size=52.0,
                )

                phase_120 = phase + 2.0943952
                sin_phase_120 = math.sin(phase_120)
                draw_plague_quad(
                    px=pos_x + math.cos(phase_120) * 10.0,
                    py=pos_y + sin_phase_120 * 10.0,
                    size=62.0,
                )

                phase_240 = phase + 4.1887903
                draw_plague_quad(
                    px=pos_x + math.cos(phase_240) * 10.0,
                    py=pos_y + math.sin(phase_240) * sin_phase_120,
                    size=62.0,
                )
                return

            fade = clamp(life * 2.5, 0.0, 1.0)
            fade_alpha = fade * alpha
            if fade_alpha <= 1e-3:
                return

            desired_size = (fade * 40.0 + 32.0) * scale
            sprite_scale = desired_size / cell_w if cell_w > 1e-6 else 0.0
            if sprite_scale <= 1e-6:
                return

            tint = self._color_from_rgba((1.0, 1.0, 1.0, fade_alpha))
            self._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=frame,
                x=sx,
                y=sy,
                scale=sprite_scale,
                rotation_rad=0.0,
                tint=tint,
            )
            return

        mapping = KNOWN_PROJ_FRAMES.get(type_id)
        if texture is None or mapping is None:
            rl.draw_circle(int(sx), int(sy), max(1.0, 3.0 * scale), rl.Color(240, 220, 160, int(255 * alpha + 0.5)))
            return
        grid, frame = mapping

        color = rl.Color(240, 220, 160, 255)
        if type_id in (ProjectileTypeId.ION_RIFLE, ProjectileTypeId.ION_MINIGUN, ProjectileTypeId.ION_CANNON):
            color = rl.Color(120, 200, 255, 255)
        elif type_id == ProjectileTypeId.FIRE_BULLETS:
            color = rl.Color(255, 170, 90, 255)
        elif type_id == ProjectileTypeId.SHRINKIFIER:
            color = rl.Color(160, 255, 170, 255)
        elif type_id == ProjectileTypeId.BLADE_GUN:
            color = rl.Color(240, 120, 255, 255)

        alpha_byte = int(clamp(clamp(life / 0.4, 0.0, 1.0) * 255.0 * alpha, 0.0, 255.0) + 0.5)
        tint = rl.Color(color.r, color.g, color.b, alpha_byte)
        self._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            x=sx,
            y=sy,
            scale=0.6 * scale,
            rotation_rad=angle,
            tint=tint,
        )

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= type_id < 8 or type_id == int(ProjectileTypeId.SPLITTER_GUN)

    @staticmethod
    def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
        base = 4.0
        if type_id == int(ProjectileTypeId.ASSAULT_RIFLE):
            base = 6.0
        elif type_id == int(ProjectileTypeId.SUBMACHINE_GUN):
            base = 8.0
        return max(2.0, base * scale)

    def _draw_bullet_trail(
        self,
        sx0: float,
        sy0: float,
        sx1: float,
        sy1: float,
        *,
        type_id: int,
        alpha: int,
        scale: float,
    ) -> bool:
        if self.bullet_trail_texture is None:
            return False
        if alpha <= 0:
            return False
        dx = sx1 - sx0
        dy = sy1 - sy0
        dist = math.hypot(dx, dy)
        if dist <= 1e-3:
            return False
        thickness = max(1.0, 2.1 * scale)
        half = thickness * 0.5
        inv = 1.0 / dist
        nx = dx * inv
        ny = dy * inv
        px = -ny
        py = nx
        ox = px * half
        oy = py * half
        x0 = sx0 - ox
        y0 = sy0 - oy
        x1 = sx0 + ox
        y1 = sy0 + oy
        x2 = sx1 + ox
        y2 = sy1 + oy
        x3 = sx1 - ox
        y3 = sy1 - oy

        # Native uses additive blending for bullet trails and sets color slots per projectile type.
        # Gauss has a distinct blue tint; most other bullet trails are neutral gray.
        if type_id == int(ProjectileTypeId.GAUSS_GUN):
            head_rgb = (51, 128, 255)  # (0.2, 0.5, 1.0)
        else:
            head_rgb = (128, 128, 128)  # (0.5, 0.5, 0.5)

        tail_rgb = (128, 128, 128)
        head = rl.Color(head_rgb[0], head_rgb[1], head_rgb[2], alpha)
        tail = rl.Color(tail_rgb[0], tail_rgb[1], tail_rgb[2], 0)
        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
        rl.rl_set_texture(self.bullet_trail_texture.id)
        rl.rl_begin(rl.RL_QUADS)
        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(0.0, 0.0)
        rl.rl_vertex2f(x0, y0)
        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(1.0, 0.0)
        rl.rl_vertex2f(x1, y1)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(1.0, 0.5)
        rl.rl_vertex2f(x2, y2)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(0.0, 0.5)
        rl.rl_vertex2f(x3, y3)
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_blend_mode()
        return True

    def _draw_sharpshooter_laser_sight(
        self,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        scale: float,
        alpha: float,
    ) -> None:
        """Laser sight overlay for the Sharpshooter perk (`projectile_render` @ 0x00422c70)."""

        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        if self.bullet_trail_texture is None:
            return

        players = self.players
        if not players:
            return

        tail_alpha = int(clamp(alpha * 0.5, 0.0, 1.0) * 255.0 + 0.5)
        head_alpha = int(clamp(alpha * 0.2, 0.0, 1.0) * 255.0 + 0.5)
        tail = rl.Color(255, 0, 0, tail_alpha)
        head = rl.Color(255, 0, 0, head_alpha)

        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
        rl.rl_set_texture(self.bullet_trail_texture.id)
        rl.rl_begin(rl.RL_QUADS)

        for player in players:
            if float(getattr(player, "health", 0.0)) <= 0.0:
                continue
            if not perk_active(player, PerkId.SHARPSHOOTER):
                continue

            aim_heading = float(getattr(player, "aim_heading", 0.0))
            dir_x = math.cos(aim_heading - math.pi / 2.0)
            dir_y = math.sin(aim_heading - math.pi / 2.0)

            start_x = float(getattr(player, "pos_x", 0.0)) + dir_x * 15.0
            start_y = float(getattr(player, "pos_y", 0.0)) + dir_y * 15.0
            end_x = float(getattr(player, "pos_x", 0.0)) + dir_x * 512.0
            end_y = float(getattr(player, "pos_y", 0.0)) + dir_y * 512.0

            sx0 = (start_x + cam_x) * scale_x
            sy0 = (start_y + cam_y) * scale_y
            sx1 = (end_x + cam_x) * scale_x
            sy1 = (end_y + cam_y) * scale_y

            dx = sx1 - sx0
            dy = sy1 - sy0
            dist = math.hypot(dx, dy)
            if dist <= 1e-3:
                continue

            thickness = max(1.0, 2.0 * scale)
            half = thickness * 0.5
            inv = 1.0 / dist
            nx = dx * inv
            ny = dy * inv
            px = -ny
            py = nx
            ox = px * half
            oy = py * half

            x0 = sx0 - ox
            y0 = sy0 - oy
            x1 = sx0 + ox
            y1 = sy0 + oy
            x2 = sx1 + ox
            y2 = sy1 + oy
            x3 = sx1 - ox
            y3 = sy1 - oy

            rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
            rl.rl_tex_coord2f(0.0, 0.0)
            rl.rl_vertex2f(x0, y0)
            rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
            rl.rl_tex_coord2f(1.0, 0.0)
            rl.rl_vertex2f(x1, y1)
            rl.rl_color4ub(head.r, head.g, head.b, head.a)
            rl.rl_tex_coord2f(1.0, 0.5)
            rl.rl_vertex2f(x2, y2)
            rl.rl_color4ub(head.r, head.g, head.b, head.a)
            rl.rl_tex_coord2f(0.0, 0.5)
            rl.rl_vertex2f(x3, y3)

        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_blend_mode()

    def _draw_secondary_projectile(self, proj: object, *, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        sx, sy = self.world_to_screen(float(getattr(proj, "pos_x", 0.0)), float(getattr(proj, "pos_y", 0.0)))
        proj_type = int(getattr(proj, "type_id", 0))
        angle = float(getattr(proj, "angle", 0.0))

        if proj_type in (1, 2, 4) and self.projs_texture is not None:
            texture = self.projs_texture
            cell_w = float(texture.width) / 4.0
            if cell_w <= 1e-6:
                return

            base_alpha = clamp(alpha * 0.9, 0.0, 1.0)
            base_tint = self._color_from_rgba((0.8, 0.8, 0.8, base_alpha))
            base_size = 14.0
            if proj_type == 2:
                base_size = 10.0
            elif proj_type == 4:
                base_size = 8.0
            sprite_scale = (base_size * scale) / cell_w

            fx_detail_1 = bool(self.config.data.get("fx_detail_1", 0)) if self.config is not None else True
            if fx_detail_1 and self.particles_texture is not None:
                particles_texture = self.particles_texture
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x0D)
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        particle_cell_w = float(particles_texture.width) / float(grid)
                        particle_cell_h = float(particles_texture.height) / float(grid)
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        src = rl.Rectangle(
                            particle_cell_w * float(col),
                            particle_cell_h * float(row),
                            max(0.0, particle_cell_w - 2.0),
                            max(0.0, particle_cell_h - 2.0),
                        )

                        dir_x = math.cos(angle - math.pi / 2.0)
                        dir_y = math.sin(angle - math.pi / 2.0)

                        def _draw_rocket_fx(
                            *,
                            size: float,
                            offset: float,
                            rgba: tuple[float, float, float, float],
                        ) -> None:
                            fx_alpha = rgba[3]
                            if fx_alpha <= 1e-3:
                                return
                            tint = self._color_from_rgba(rgba)
                            fx_sx = sx - dir_x * offset * scale
                            fx_sy = sy - dir_y * offset * scale
                            dst_size = size * scale
                            dst = rl.Rectangle(float(fx_sx), float(fx_sy), float(dst_size), float(dst_size))
                            origin = rl.Vector2(dst_size * 0.5, dst_size * 0.5)
                            rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)

                        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                        # Large bloom around the rocket (effect_id=0x0D).
                        _draw_rocket_fx(size=140.0, offset=5.0, rgba=(1.0, 1.0, 1.0, alpha * 0.48))

                        if proj_type == 4:
                            _draw_rocket_fx(size=30.0, offset=9.0, rgba=(0.7, 0.7, 1.0, alpha * 0.158))
                        elif proj_type == 2:
                            _draw_rocket_fx(size=40.0, offset=9.0, rgba=(1.0, 1.0, 1.0, alpha * 0.58))
                        else:
                            _draw_rocket_fx(size=60.0, offset=9.0, rgba=(1.0, 1.0, 1.0, alpha * 0.68))

                        rl.end_blend_mode()
            self._draw_atlas_sprite(
                texture,
                grid=4,
                frame=3,
                x=sx,
                y=sy,
                scale=sprite_scale,
                rotation_rad=angle,
                tint=base_tint,
            )
            return

        if proj_type == 4:
            rl.draw_circle(int(sx), int(sy), max(1.0, 12.0 * scale), rl.Color(200, 120, 255, int(255 * alpha + 0.5)))
            return
        if proj_type == 3:
            # Secondary projectile detonation visuals (secondary_projectile_update + render).
            t = clamp(float(getattr(proj, "vel_x", 0.0)), 0.0, 1.0)
            det_scale = float(getattr(proj, "vel_y", 1.0))
            fade = (1.0 - t) * alpha
            if fade <= 1e-3 or det_scale <= 1e-6:
                return
            if self.particles_texture is None:
                radius = det_scale * t * 80.0
                alpha_byte = int(clamp((1.0 - t) * 180.0 * alpha, 0.0, 255.0) + 0.5)
                color = rl.Color(255, 180, 100, alpha_byte)
                rl.draw_circle_lines(int(sx), int(sy), max(1.0, radius * scale), color)
                return

            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x0D)
            if atlas is None:
                return
            grid = SIZE_CODE_GRID.get(int(atlas.size_code))
            if not grid:
                return
            frame = int(atlas.frame)
            col = frame % grid
            row = frame // grid
            cell_w = float(self.particles_texture.width) / float(grid)
            cell_h = float(self.particles_texture.height) / float(grid)
            src = rl.Rectangle(
                cell_w * float(col),
                cell_h * float(row),
                max(0.0, cell_w - 2.0),
                max(0.0, cell_h - 2.0),
            )

            def _draw_detonation_quad(*, size: float, alpha_mul: float) -> None:
                a = fade * alpha_mul
                if a <= 1e-3:
                    return
                dst_size = size * scale
                if dst_size <= 1e-3:
                    return
                tint = self._color_from_rgba((1.0, 0.6, 0.1, a))
                dst = rl.Rectangle(float(sx), float(sy), float(dst_size), float(dst_size))
                origin = rl.Vector2(float(dst_size) * 0.5, float(dst_size) * 0.5)
                rl.draw_texture_pro(self.particles_texture, src, dst, origin, 0.0, tint)

            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
            _draw_detonation_quad(size=det_scale * t * 64.0, alpha_mul=1.0)
            _draw_detonation_quad(size=det_scale * t * 200.0, alpha_mul=0.3)
            rl.end_blend_mode()
            return
        rl.draw_circle(int(sx), int(sy), max(1.0, 4.0 * scale), rl.Color(200, 200, 220, int(200 * alpha + 0.5)))

    def _draw_particle_pool(self, *, cam_x: float, cam_y: float, scale_x: float, scale_y: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.particles_texture
        if texture is None:
            return

        particles = self.state.particles.entries
        if not any(entry.active for entry in particles):
            return

        scale = (scale_x + scale_y) * 0.5

        def src_rect(effect_id: int) -> rl.Rectangle | None:
            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(effect_id))
            if atlas is None:
                return None
            grid = SIZE_CODE_GRID.get(int(atlas.size_code))
            if not grid:
                return None
            frame = int(atlas.frame)
            col = frame % grid
            row = frame // grid
            cell_w = float(texture.width) / float(grid)
            cell_h = float(texture.height) / float(grid)
            return rl.Rectangle(
                cell_w * float(col),
                cell_h * float(row),
                max(0.0, cell_w - 2.0),
                max(0.0, cell_h - 2.0),
            )

        src_large = src_rect(13)
        src_normal = src_rect(12)
        src_style_8 = src_rect(2)
        if src_normal is None or src_style_8 is None:
            return

        fx_detail_1 = bool(self.config.data.get("fx_detail_1", 0)) if self.config is not None else True

        rl.begin_blend_mode(rl.BLEND_ADDITIVE)

        if fx_detail_1 and src_large is not None:
            alpha_byte = int(clamp(alpha * 0.065, 0.0, 1.0) * 255.0 + 0.5)
            tint = rl.Color(255, 255, 255, alpha_byte)
            for idx, entry in enumerate(particles):
                if not entry.active or (idx % 2) or int(entry.style_id) == 8:
                    continue
                radius = (math.sin((1.0 - float(entry.intensity)) * 1.5707964) + 0.1) * 55.0 + 4.0
                radius = max(radius, 16.0)
                size = max(0.0, radius * 2.0 * scale)
                if size <= 0.0:
                    continue
                sx = (float(entry.pos_x) + cam_x) * scale_x
                sy = (float(entry.pos_y) + cam_y) * scale_y
                dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                origin = rl.Vector2(float(size) * 0.5, float(size) * 0.5)
                rl.draw_texture_pro(texture, src_large, dst, origin, 0.0, tint)

        for entry in particles:
            if not entry.active or int(entry.style_id) == 8:
                continue
            radius = math.sin((1.0 - float(entry.intensity)) * 1.5707964) * 24.0
            if int(entry.style_id) == 1:
                radius *= 0.8
            radius = max(radius, 2.0)
            size = max(0.0, radius * 2.0 * scale)
            if size <= 0.0:
                continue
            sx = (float(entry.pos_x) + cam_x) * scale_x
            sy = (float(entry.pos_y) + cam_y) * scale_y
            dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
            origin = rl.Vector2(float(size) * 0.5, float(size) * 0.5)
            rotation_deg = float(entry.spin) * _RAD_TO_DEG
            tint = self._color_from_rgba((entry.scale_x, entry.scale_y, entry.scale_z, float(entry.age) * alpha))
            rl.draw_texture_pro(texture, src_normal, dst, origin, rotation_deg, tint)

        alpha_byte = int(clamp(alpha, 0.0, 1.0) * 255.0 + 0.5)
        for entry in particles:
            if not entry.active or int(entry.style_id) != 8:
                continue
            wobble = math.sin(float(entry.spin)) * 3.0
            half_h = (wobble + 15.0) * float(entry.scale_x) * 7.0
            half_w = (15.0 - wobble) * float(entry.scale_x) * 7.0
            w = max(0.0, half_w * 2.0 * scale)
            h = max(0.0, half_h * 2.0 * scale)
            if w <= 0.0 or h <= 0.0:
                continue
            sx = (float(entry.pos_x) + cam_x) * scale_x
            sy = (float(entry.pos_y) + cam_y) * scale_y
            dst = rl.Rectangle(float(sx), float(sy), float(w), float(h))
            origin = rl.Vector2(float(w) * 0.5, float(h) * 0.5)
            tint = rl.Color(255, 255, 255, int(float(entry.age) * alpha_byte + 0.5))
            rl.draw_texture_pro(texture, src_style_8, dst, origin, 0.0, tint)

        rl.end_blend_mode()

    def _draw_sprite_effect_pool(
        self,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        alpha: float = 1.0,
    ) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        if self.config is not None and not bool(self.config.data.get("fx_detail_2", 0)):
            return
        texture = self.particles_texture
        if texture is None:
            return

        effects = self.state.sprite_effects.entries
        if not any(entry.active for entry in effects):
            return

        atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x11)
        if atlas is None:
            return
        grid = SIZE_CODE_GRID.get(int(atlas.size_code))
        if not grid:
            return
        frame = int(atlas.frame)
        col = frame % grid
        row = frame // grid
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        src = rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)
        scale = (scale_x + scale_y) * 0.5

        rl.begin_blend_mode(rl.BLEND_ALPHA)
        for entry in effects:
            if not entry.active:
                continue
            size = float(entry.scale) * scale
            if size <= 0.0:
                continue
            sx = (float(entry.pos_x) + cam_x) * scale_x
            sy = (float(entry.pos_y) + cam_y) * scale_y
            dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
            origin = rl.Vector2(float(size) * 0.5, float(size) * 0.5)
            rotation_deg = float(entry.rotation) * _RAD_TO_DEG
            tint = self._color_from_rgba((entry.color_r, entry.color_g, entry.color_b, float(entry.color_a) * alpha))
            rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)
        rl.end_blend_mode()

    def _draw_effect_pool(self, *, cam_x: float, cam_y: float, scale_x: float, scale_y: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.particles_texture
        if texture is None:
            return

        effects = self.state.effects.entries
        if not any(entry.flags and entry.age >= 0.0 for entry in effects):
            return

        scale = (scale_x + scale_y) * 0.5

        src_cache: dict[int, rl.Rectangle] = {}

        def src_rect(effect_id: int) -> rl.Rectangle | None:
            cached = src_cache.get(effect_id)
            if cached is not None:
                return cached

            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(effect_id))
            if atlas is None:
                return None
            grid = SIZE_CODE_GRID.get(int(atlas.size_code))
            if not grid:
                return None
            frame = int(atlas.frame)
            col = frame % grid
            row = frame // grid
            cell_w = float(texture.width) / float(grid)
            cell_h = float(texture.height) / float(grid)
            # Native effect pool clamps UVs to (cell_size - 2px) to avoid bleeding.
            src = rl.Rectangle(
                cell_w * float(col),
                cell_h * float(row),
                max(0.0, cell_w - 2.0),
                max(0.0, cell_h - 2.0),
            )
            src_cache[effect_id] = src
            return src

        def draw_entry(entry: object) -> None:
            effect_id = int(getattr(entry, "effect_id", 0))
            src = src_rect(effect_id)
            if src is None:
                return

            pos_x = float(getattr(entry, "pos_x", 0.0))
            pos_y = float(getattr(entry, "pos_y", 0.0))
            sx = (pos_x + cam_x) * scale_x
            sy = (pos_y + cam_y) * scale_y

            half_w = float(getattr(entry, "half_width", 0.0))
            half_h = float(getattr(entry, "half_height", 0.0))
            local_scale = float(getattr(entry, "scale", 1.0))
            w = max(0.0, half_w * 2.0 * local_scale * scale)
            h = max(0.0, half_h * 2.0 * local_scale * scale)
            if w <= 0.0 or h <= 0.0:
                return

            rotation_deg = float(getattr(entry, "rotation", 0.0)) * _RAD_TO_DEG
            tint = self._color_from_rgba(
                (
                    float(getattr(entry, "color_r", 1.0)),
                    float(getattr(entry, "color_g", 1.0)),
                    float(getattr(entry, "color_b", 1.0)),
                    float(getattr(entry, "color_a", 1.0)),
                )
            )
            tint = rl.Color(tint.r, tint.g, tint.b, int(tint.a * alpha + 0.5))

            dst = rl.Rectangle(float(sx), float(sy), float(w), float(h))
            origin = rl.Vector2(float(w) * 0.5, float(h) * 0.5)
            rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

        rl.begin_blend_mode(rl.BLEND_ALPHA)
        for entry in effects:
            if not entry.flags or entry.age < 0.0:
                continue
            if int(entry.flags) & 0x40:
                draw_entry(entry)
        rl.end_blend_mode()

        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
        for entry in effects:
            if not entry.flags or entry.age < 0.0:
                continue
            if not (int(entry.flags) & 0x40):
                draw_entry(entry)
        rl.end_blend_mode()

    def draw(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        entity_alpha = clamp(float(entity_alpha), 0.0, 1.0)
        clear_color = rl.Color(10, 10, 12, 255)
        screen_w, screen_h = self._camera_screen_size()
        cam_x, cam_y = self._clamp_camera(self.camera_x, self.camera_y, screen_w, screen_h)
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        if self.ground is None:
            rl.clear_background(clear_color)
        else:
            rl.clear_background(clear_color)
            self.ground.draw(cam_x, cam_y, screen_w=screen_w, screen_h=screen_h)
        scale = (scale_x + scale_y) * 0.5

        # World bounds for debug if terrain is missing.
        if self.ground is None:
            x0 = (0.0 + cam_x) * scale_x
            y0 = (0.0 + cam_y) * scale_y
            x1 = (float(self.world_size) + cam_x) * scale_x
            y1 = (float(self.world_size) + cam_y) * scale_y
            rl.draw_rectangle_lines(int(x0), int(y0), int(x1 - x0), int(y1 - y0), rl.Color(40, 40, 55, 255))

        if entity_alpha <= 1e-3:
            return

        alpha_test = True
        if self.ground is not None:
            alpha_test = bool(getattr(self.ground, "alpha_test", True))

        with _maybe_alpha_test(bool(alpha_test)):
            trooper_texture = self.creature_textures.get(CREATURE_ASSET.get(CreatureTypeId.TROOPER))
            particles_texture = self.particles_texture
            monster_vision = bool(self.players) and perk_active(self.players[0], PerkId.MONSTER_VISION)
            monster_vision_src: rl.Rectangle | None = None
            if monster_vision and particles_texture is not None:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x10)
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        cell_w = float(particles_texture.width) / float(grid)
                        cell_h = float(particles_texture.height) / float(grid)
                        monster_vision_src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )

            def draw_player(player: object) -> None:
                if trooper_texture is not None:
                    self._draw_player_trooper_sprite(
                        trooper_texture,
                        player,
                        cam_x=cam_x,
                        cam_y=cam_y,
                        scale_x=scale_x,
                        scale_y=scale_y,
                        scale=scale,
                        alpha=entity_alpha,
                    )
                    return

                sx = (player.pos_x + cam_x) * scale_x
                sy = (player.pos_y + cam_y) * scale_y
                tint = rl.Color(90, 190, 120, int(255 * entity_alpha + 0.5))
                rl.draw_circle(int(sx), int(sy), max(1.0, 14.0 * scale), tint)

            for player in self.players:
                if player.health <= 0.0:
                    draw_player(player)

            creature_type_order = {
                int(CreatureTypeId.ZOMBIE): 0,
                int(CreatureTypeId.SPIDER_SP1): 1,
                int(CreatureTypeId.SPIDER_SP2): 2,
                int(CreatureTypeId.ALIEN): 3,
                int(CreatureTypeId.LIZARD): 4,
            }
            creatures = [
                (idx, creature)
                for idx, creature in enumerate(self.creatures.entries)
                if creature.active
            ]
            creatures.sort(key=lambda item: (creature_type_order.get(int(getattr(item[1], "type_id", -1)), 999), item[0]))
            for _idx, creature in creatures:
                sx = (creature.x + cam_x) * scale_x
                sy = (creature.y + cam_y) * scale_y
                hitbox_size = float(creature.hitbox_size)
                try:
                    type_id = CreatureTypeId(int(creature.type_id))
                except ValueError:
                    type_id = None
                asset = CREATURE_ASSET.get(type_id) if type_id is not None else None
                texture = self.creature_textures.get(asset) if asset is not None else None
                if monster_vision and particles_texture is not None and monster_vision_src is not None:
                    fade = monster_vision_fade_alpha(hitbox_size)
                    mv_alpha = fade * entity_alpha
                    if mv_alpha > 1e-3:
                        size = 90.0 * scale
                        dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(255, 255, 0, int(clamp(mv_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.draw_texture_pro(particles_texture, monster_vision_src, dst, origin, 0.0, tint)
                if texture is None:
                    tint = rl.Color(220, 90, 90, int(255 * entity_alpha + 0.5))
                    rl.draw_circle(int(sx), int(sy), max(1.0, creature.size * 0.5 * scale), tint)
                    continue

                info = CREATURE_ANIM.get(type_id) if type_id is not None else None
                if info is None:
                    continue

                tint_alpha = float(creature.tint_a)
                if hitbox_size < 0.0:
                    # Mirrors the main-pass alpha fade when hitbox_size ramps negative.
                    tint_alpha = max(0.0, tint_alpha + hitbox_size * 0.1)
                tint_alpha = clamp(tint_alpha * entity_alpha, 0.0, 1.0)
                tint = self._color_from_rgba((creature.tint_r, creature.tint_g, creature.tint_b, tint_alpha))

                size_scale = clamp(float(creature.size) / 64.0, 0.25, 2.0)
                fx_detail = bool(self.config.data.get("fx_detail_0", 0)) if self.config is not None else True
                # Mirrors `creature_render_type`: the "shadow-ish" pass is gated by fx_detail_0
                # and is disabled when the Monster Vision perk is active.
                shadow = fx_detail and (not self.players or not perk_active(self.players[0], PerkId.MONSTER_VISION))
                long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (
                    creature.flags & CreatureFlags.ANIM_LONG_STRIP
                ) != 0
                phase = float(creature.anim_phase)
                if long_strip:
                    if hitbox_size < 0.0:
                        # Negative phase selects the fallback "corpse" frame in creature_render_type.
                        phase = -1.0
                    elif hitbox_size < 16.0:
                        # Death staging: while hitbox_size ramps down (16..0), creature_render_type
                        # selects frames via `__ftol((base_frame + 15) - hitbox_size)`.
                        phase = float(info.base + 0x0F) - hitbox_size - 0.5

                shadow_alpha = None
                if shadow:
                    # Shadow pass uses tint_a * 0.4 and fades much faster for corpses (hitbox_size < 0).
                    shadow_a = float(creature.tint_a) * 0.4
                    if hitbox_size < 0.0:
                        shadow_a += hitbox_size * (0.5 if long_strip else 0.1)
                        shadow_a = max(0.0, shadow_a)
                    shadow_alpha = int(clamp(shadow_a * entity_alpha * 255.0, 0.0, 255.0) + 0.5)
                self._draw_creature_sprite(
                    texture,
                    type_id=type_id or CreatureTypeId.ZOMBIE,
                    flags=creature.flags,
                    phase=phase,
                    mirror_long=bool(info.mirror) and hitbox_size >= 16.0,
                    shadow_alpha=shadow_alpha,
                    world_x=float(creature.x),
                    world_y=float(creature.y),
                    rotation_rad=float(creature.heading) - math.pi / 2.0,
                    scale=scale,
                    size_scale=size_scale,
                    tint=tint,
                    shadow=shadow,
                )

            freeze_timer = float(self.state.bonuses.freeze)
            if particles_texture is not None and freeze_timer > 0.0:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(0x0E)
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

                        fade = 1.0 if freeze_timer >= 1.0 else clamp(freeze_timer, 0.0, 1.0)
                        freeze_alpha = clamp(fade * entity_alpha * 0.7, 0.0, 1.0)
                        if freeze_alpha > 1e-3:
                            tint = rl.Color(255, 255, 255, int(freeze_alpha * 255.0 + 0.5))
                            rl.begin_blend_mode(rl.BLEND_ALPHA)
                            for idx, creature in enumerate(self.creatures.entries):
                                if not creature.active:
                                    continue
                                size = float(creature.size) * scale
                                if size <= 1e-3:
                                    continue
                                sx = (creature.x + cam_x) * scale_x
                                sy = (creature.y + cam_y) * scale_y
                                dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
                                origin = rl.Vector2(size * 0.5, size * 0.5)
                                rotation_deg = (float(idx) * 0.01 + float(creature.heading)) * _RAD_TO_DEG
                                rl.draw_texture_pro(particles_texture, src, dst, origin, rotation_deg, tint)
                            rl.end_blend_mode()

            for player in self.players:
                if player.health > 0.0:
                    draw_player(player)

            self._draw_sharpshooter_laser_sight(
                cam_x=cam_x,
                cam_y=cam_y,
                scale_x=scale_x,
                scale_y=scale_y,
                scale=scale,
                alpha=entity_alpha,
            )

            for proj_index, proj in enumerate(self.state.projectiles.entries):
                if not proj.active:
                    continue
                self._draw_projectile(proj, proj_index=proj_index, scale=scale, alpha=entity_alpha)

            self._draw_particle_pool(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, alpha=entity_alpha)

            for proj in self.state.secondary_projectiles.entries:
                if not proj.active:
                    continue
                self._draw_secondary_projectile(proj, scale=scale, alpha=entity_alpha)

            self._draw_sprite_effect_pool(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, alpha=entity_alpha)
            self._draw_effect_pool(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, alpha=entity_alpha)
            self._draw_bonus_pickups(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, scale=scale, alpha=entity_alpha)
            self._draw_bonus_hover_labels(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, alpha=entity_alpha)

            if draw_aim_indicators and (not self.demo_mode_active):
                for player in self.players:
                    if player.health <= 0.0:
                        continue
                    aim_x = float(getattr(player, "aim_x", player.pos_x))
                    aim_y = float(getattr(player, "aim_y", player.pos_y))
                    dist = math.hypot(aim_x - float(player.pos_x), aim_y - float(player.pos_y))
                    radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
                    sx = (aim_x + cam_x) * scale_x
                    sy = (aim_y + cam_y) * scale_y
                    screen_radius = max(1.0, radius * scale)
                    self._draw_aim_circle(x=sx, y=sy, radius=screen_radius, alpha=entity_alpha)
                    reload_timer = float(getattr(player, "reload_timer", 0.0))
                    reload_max = float(getattr(player, "reload_timer_max", 0.0))
                    if reload_max > 1e-6 and reload_timer > 1e-6:
                        progress = reload_timer / reload_max
                        if progress > 0.0:
                            ms = int(progress * 60000.0)
                            self._draw_clock_gauge(x=float(int(sx)), y=float(int(sy)), ms=ms, scale=scale, alpha=entity_alpha)

    def world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        return (x + cam_x) * scale_x, (y + cam_y) * scale_y

    def screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        inv_x = 1.0 / scale_x if scale_x > 0 else 1.0
        inv_y = 1.0 / scale_y if scale_y > 0 else 1.0
        return x * inv_x - cam_x, y * inv_y - cam_y
