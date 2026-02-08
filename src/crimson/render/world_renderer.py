from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING

import pyray as rl
from raylib import defines as rd

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.terrain_render import _maybe_alpha_test

from ..bonuses import BONUS_BY_ID, BonusId
from ..creatures.anim import creature_anim_select_frame
from ..creatures.spawn import CreatureFlags, CreatureTypeId
from ..effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from ..gameplay import bonus_find_aim_hover_entry, bonus_label_for_entry, perk_active
from ..perks import PerkId
from ..projectiles import ProjectileTypeId
from ..sim.world_defs import (
    CREATURE_ANIM,
    CREATURE_ASSET,
    KNOWN_PROJ_FRAMES,
)
from ..weapons import WEAPON_BY_ID
from .projectile_draw_registry import ProjectileDrawCtx, draw_projectile_from_registry
from .projectile_render_registry import known_proj_rgb
from .secondary_projectile_draw_registry import SecondaryProjectileDrawCtx, draw_secondary_projectile_from_registry
from .frame import RenderFrame

if TYPE_CHECKING:
    from pathlib import Path

    from grim.config import CrimsonConfig
    from grim.terrain_render import GroundRenderer

    from ..creatures.runtime import CreaturePool
    from ..game_world import GameWorld
    from ..gameplay import GameplayState, PlayerState
    from ..projectiles import Projectile, SecondaryProjectile

_RAD_TO_DEG = 57.29577951308232


def monster_vision_fade_alpha(hitbox_size: float) -> float:
    if float(hitbox_size) >= 0.0:
        return 1.0
    return clamp((float(hitbox_size) + 10.0) * 0.1, 0.0, 1.0)


@dataclass(slots=True)
class WorldRenderer:
    _world: GameWorld
    _render_frame: RenderFrame | None = None
    _small_font: SmallFontData | None = None

    @property
    def assets_dir(self) -> Path:
        frame = self._render_frame
        if frame is not None:
            return frame.assets_dir
        return self._world.assets_dir

    @property
    def missing_assets(self) -> list[str]:
        frame = self._render_frame
        if frame is not None:
            return frame.missing_assets
        return self._world.missing_assets

    @property
    def world_size(self) -> float:
        frame = self._render_frame
        if frame is not None:
            return frame.world_size
        return self._world.world_size

    @property
    def demo_mode_active(self) -> bool:
        frame = self._render_frame
        if frame is not None:
            return frame.demo_mode_active
        return self._world.demo_mode_active

    @property
    def config(self) -> CrimsonConfig | None:
        frame = self._render_frame
        if frame is not None:
            return frame.config
        return self._world.config

    @property
    def camera(self) -> Vec2:
        frame = self._render_frame
        if frame is not None:
            return frame.camera
        return self._world.camera

    @property
    def ground(self) -> GroundRenderer | None:
        frame = self._render_frame
        if frame is not None:
            return frame.ground
        return self._world.ground

    @property
    def state(self) -> GameplayState:
        frame = self._render_frame
        if frame is not None:
            return frame.state
        return self._world.state

    @property
    def players(self) -> list[PlayerState]:
        frame = self._render_frame
        if frame is not None:
            return frame.players
        return self._world.players

    @property
    def creatures(self) -> CreaturePool:
        frame = self._render_frame
        if frame is not None:
            return frame.creatures
        return self._world.creatures

    @property
    def creature_textures(self) -> dict[str, rl.Texture]:
        frame = self._render_frame
        if frame is not None:
            return frame.creature_textures
        return self._world.creature_textures

    @property
    def projs_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.projs_texture
        return self._world.projs_texture

    @property
    def particles_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.particles_texture
        return self._world.particles_texture

    @property
    def bullet_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bullet_texture
        return self._world.bullet_texture

    @property
    def bullet_trail_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bullet_trail_texture
        return self._world.bullet_trail_texture

    @property
    def arrow_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.arrow_texture
        return self._world.arrow_texture

    @property
    def bonuses_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bonuses_texture
        return self._world.bonuses_texture

    @property
    def bodyset_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bodyset_texture
        return self._world.bodyset_texture

    @property
    def clock_table_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.clock_table_texture
        return self._world.clock_table_texture

    @property
    def clock_pointer_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.clock_pointer_texture
        return self._world.clock_pointer_texture

    @property
    def muzzle_flash_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.muzzle_flash_texture
        return self._world.muzzle_flash_texture

    @property
    def wicons_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.wicons_texture
        return self._world.wicons_texture

    @property
    def elapsed_ms(self) -> float:
        frame = self._render_frame
        if frame is not None:
            return frame.elapsed_ms
        return float(self._world._elapsed_ms)

    @property
    def bonus_anim_phase(self) -> float:
        frame = self._render_frame
        if frame is not None:
            return frame.bonus_anim_phase
        return float(self._world._bonus_anim_phase)

    def _ensure_small_font(self) -> SmallFontData | None:
        if self._small_font is not None:
            return self._small_font
        try:
            # Keep UI text consistent with the HUD/menu font when available.
            self._small_font = load_small_font(self.assets_dir, self.missing_assets)
        except Exception:
            self._small_font = None
        return self._small_font

    def _camera_screen_size(self) -> Vec2:
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
        return Vec2(screen_w, screen_h)

    def _clamp_camera(self, camera: Vec2, screen_size: Vec2) -> Vec2:
        min_x = screen_size.x - float(self.world_size)
        min_y = screen_size.y - float(self.world_size)
        return camera.clamp_rect(min_x, min_y, -1.0, -1.0)

    def _world_params(self) -> tuple[Vec2, Vec2]:
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        screen_size = self._camera_screen_size()
        camera = self._clamp_camera(self.camera, screen_size)
        scale_x = out_size.x / screen_size.x if screen_size.x > 0 else 1.0
        scale_y = out_size.y / screen_size.y if screen_size.y > 0 else 1.0
        return camera, Vec2(scale_x, scale_y)

    @staticmethod
    def _world_to_screen_with(pos: Vec2, *, camera: Vec2, view_scale: Vec2) -> Vec2:
        return (pos + camera).mul_components(view_scale)

    @staticmethod
    def _view_scale_avg(view_scale: Vec2) -> float:
        return view_scale.avg_component()

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
        camera: Vec2,
        view_scale: Vec2,
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
                screen = self._world_to_screen_with(bonus.pos, camera=camera, view_scale=view_scale)
                tint = rl.Color(220, 220, 90, int(255 * alpha + 0.5))
                rl.draw_circle(int(screen.x), int(screen.y), max(1.0, 10.0 * scale), tint)
            return

        bubble_src = self._bonus_icon_src(self.bonuses_texture, 0)
        bubble_size = 32.0 * scale

        for idx, bonus in enumerate(self.state.bonus_pool.entries):
            if bonus.bonus_id == 0:
                continue

            fade = self._bonus_fade(float(bonus.time_left), float(bonus.time_max))
            bubble_alpha = clamp(fade * 0.9, 0.0, 1.0) * alpha

            screen = self._world_to_screen_with(bonus.pos, camera=camera, view_scale=view_scale)
            bubble_dst = rl.Rectangle(screen.x, screen.y, bubble_size, bubble_size)
            bubble_origin = rl.Vector2(bubble_size * 0.5, bubble_size * 0.5)
            tint = rl.Color(255, 255, 255, int(bubble_alpha * 255.0 + 0.5))
            rl.draw_texture_pro(self.bonuses_texture, bubble_src, bubble_dst, bubble_origin, 0.0, tint)

            bonus_id = int(bonus.bonus_id)
            if bonus_id == int(BonusId.WEAPON):
                weapon = WEAPON_BY_ID.get(int(bonus.amount))
                icon_index = int(weapon.icon_index) if weapon is not None and weapon.icon_index is not None else None
                if icon_index is None or not (0 <= icon_index <= 31) or self.wicons_texture is None:
                    continue

                pulse = math.sin(float(self.bonus_anim_phase)) ** 4 * 0.25 + 0.75
                icon_scale = fade * pulse
                if icon_scale <= 1e-3:
                    continue

                src = self._weapon_icon_src(self.wicons_texture, icon_index)
                w = 60.0 * icon_scale * scale
                h = 30.0 * icon_scale * scale
                dst = rl.Rectangle(screen.x, screen.y, w, h)
                origin = rl.Vector2(w * 0.5, h * 0.5)
                rl.draw_texture_pro(self.wicons_texture, src, dst, origin, 0.0, tint)
                continue

            meta = BONUS_BY_ID.get(bonus_id)
            icon_id = int(meta.icon_id) if meta is not None and meta.icon_id is not None else None
            if icon_id is None or icon_id < 0:
                continue
            if bonus_id == int(BonusId.POINTS) and int(bonus.amount) == 1000:
                icon_id += 1

            pulse = math.sin(float(idx) + float(self.bonus_anim_phase)) ** 4 * 0.25 + 0.75
            icon_scale = fade * pulse
            if icon_scale <= 1e-3:
                continue

            src = self._bonus_icon_src(self.bonuses_texture, icon_id)
            size = 32.0 * icon_scale * scale
            rotation_rad = math.sin(float(idx) - float(self.elapsed_ms) * 0.003) * 0.2
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rl.draw_texture_pro(self.bonuses_texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), tint)

    def _draw_bonus_hover_labels(
        self,
        *,
        camera: Vec2,
        view_scale: Vec2,
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
            label = bonus_label_for_entry(entry)
            if not label:
                continue

            aim = player.aim
            aim_screen = self._world_to_screen_with(aim, camera=camera, view_scale=view_scale)
            x = aim_screen.x + 16.0
            y = aim_screen.y - 7.0

            if font is not None:
                text_w = measure_small_text_width(font, label, text_scale)
            else:
                text_w = float(rl.measure_text(label, int(18 * text_scale)))
            if x + text_w > screen_w:
                x = max(0.0, screen_w - text_w)

            if font is not None:
                draw_small_text(font, label, Vec2(x + 1.0, y + 1.0), text_scale, shadow)
                draw_small_text(font, label, Vec2(x, y), text_scale, color)
            else:
                rl.draw_text(label, int(x) + 1, int(y) + 1, int(18 * text_scale), shadow)
                rl.draw_text(label, int(x), int(y), int(18 * text_scale), color)

    def _draw_atlas_sprite(
        self,
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        pos: Vec2,
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
        dst = rl.Rectangle(pos.x, pos.y, w, h)
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

    def _draw_aim_circle(self, *, center: Vec2, radius: float, alpha: float = 1.0) -> None:
        if radius <= 1e-3:
            return
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return

        fill_a = int(77 * alpha + 0.5)  # ui_render_aim_indicators: rgba(0,0,0.1,0.3)
        outline_a = int(255 * 0.55 * alpha + 0.5)
        fill = rl.Color(0, 0, 26, fill_a)
        outline = rl.Color(255, 255, 255, outline_a)

        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)

        # The original uses a triangle fan (polygons). Raylib provides circle
        # primitives that still use triangles internally, but allow higher
        # segment counts for a smoother result when scaled.
        seg_count = max(self._grim2d_circle_segments_filled(radius), 64, int(radius))
        center_rl = center.to_rl()
        rl.draw_circle_sector(center_rl, float(radius), 0.0, 360.0, int(seg_count), fill)

        seg_count = max(self._grim2d_circle_segments_outline(radius), int(seg_count))
        # grim_draw_circle_outline draws a 2px-thick ring (outer radius = r + 2).
        # The exe binds bulletTrail, but that texture is white; the visual intent is
        # a subtle white outline around the filled spread circle.
        rl.draw_ring(center_rl, float(radius), float(radius + 2.0), 0.0, 360.0, int(seg_count), outline)

        rl.rl_set_texture(0)
        rl.end_blend_mode()

    def _draw_clock_gauge(self, *, pos: Vec2, ms: int, scale: float, alpha: float = 1.0) -> None:
        if self.clock_table_texture is None or self.clock_pointer_texture is None:
            return
        size = 32.0 * scale
        if size <= 1e-3:
            return
        tint = rl.Color(255, 255, 255, int(clamp(float(alpha), 0.0, 1.0) * 255.0 + 0.5))
        half = size * 0.5

        table_src = rl.Rectangle(
            0.0, 0.0, float(self.clock_table_texture.width), float(self.clock_table_texture.height)
        )
        table_dst = rl.Rectangle(pos.x, pos.y, size, size)
        rl.draw_texture_pro(self.clock_table_texture, table_src, table_dst, rl.Vector2(0.0, 0.0), 0.0, tint)

        seconds = int(ms) // 1000
        pointer_src = rl.Rectangle(
            0.0,
            0.0,
            float(self.clock_pointer_texture.width),
            float(self.clock_pointer_texture.height),
        )
        pointer_dst = rl.Rectangle(pos.x + half, pos.y + half, size, size)
        origin = rl.Vector2(half, half)
        rotation_deg = float(seconds) * 6.0
        rl.draw_texture_pro(self.clock_pointer_texture, pointer_src, pointer_dst, origin, rotation_deg, tint)

    def _hud_indicator_enabled(self, player_index: int) -> bool:
        if self.config is None:
            return True
        raw = self.config.data.get("hud_indicators", b"\x01\x01")
        if not isinstance(raw, (bytes, bytearray)):
            return True
        idx = int(player_index)
        if idx < 0:
            return False
        if idx >= len(raw):
            return True
        return bool(raw[idx])

    def _direction_arrow_tint(self, player_index: int, *, alpha: float) -> rl.Color:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if len(self.players) == 2:
            if int(player_index) == 0:
                return rl.Color(204, 230, 255, int(153.0 * alpha + 0.5))
            return rl.Color(255, 230, 204, int(153.0 * alpha + 0.5))
        return rl.Color(255, 255, 255, int(77.0 * alpha + 0.5))

    def _draw_direction_arrows(self, *, camera: Vec2, view_scale: Vec2, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        arrow = self.arrow_texture
        if arrow is None:
            return

        src = rl.Rectangle(0.0, 0.0, float(arrow.width), float(arrow.height))
        width = max(1.0, float(arrow.width) * scale)
        height = max(1.0, float(arrow.height) * scale)
        origin = rl.Vector2(width * 0.5, height * 0.5)

        for player in self.players:
            if float(getattr(player, "health", 0.0)) <= 0.0:
                continue
            index = int(getattr(player, "index", 0))
            if not self._hud_indicator_enabled(index):
                continue

            heading = float(getattr(player, "heading", 0.0))
            marker_pos = player.pos + Vec2.from_heading(heading) * 60.0
            screen = self._world_to_screen_with(marker_pos, camera=camera, view_scale=view_scale)
            dst = rl.Rectangle(screen.x, screen.y, width, height)
            tint = self._direction_arrow_tint(index, alpha=alpha)
            rl.draw_texture_pro(arrow, src, dst, origin, float(heading * _RAD_TO_DEG), tint)

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

    def _draw_projectile(self, proj: Projectile, *, proj_index: int = 0, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.projs_texture
        type_id = int(proj.type_id)
        proj_pos = proj.pos
        screen = self.world_to_screen(proj_pos)
        life = float(proj.life_timer)
        angle = float(proj.angle)

        ctx = ProjectileDrawCtx(
            renderer=self,
            proj=proj,
            proj_index=int(proj_index),
            texture=texture,
            type_id=int(type_id),
            pos=proj_pos,
            screen_pos=screen,
            life=float(life),
            angle=float(angle),
            scale=float(scale),
            alpha=float(alpha),
        )
        if draw_projectile_from_registry(ctx):
            return

        mapping = KNOWN_PROJ_FRAMES.get(type_id)
        if mapping is None:
            return
        if texture is None:
            if life < 0.39:
                return
            rl.draw_circle(
                int(screen.x), int(screen.y), max(1.0, 2.0 * scale), rl.Color(180, 180, 180, int(180 * alpha + 0.5))
            )
            return
        grid, frame = mapping

        alpha_byte = int(clamp(clamp(life / 0.4, 0.0, 1.0) * 255.0 * alpha, 0.0, 255.0) + 0.5)
        r, g, b = known_proj_rgb(type_id)
        tint = rl.Color(int(r), int(g), int(b), alpha_byte)
        self._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            pos=screen,
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
        start: Vec2,
        end: Vec2,
        *,
        type_id: int,
        alpha: int,
        scale: float,
        angle: float,
    ) -> bool:
        if self.bullet_trail_texture is None:
            return False
        if alpha <= 0:
            return False

        segment = end - start
        direction, dist = segment.normalized_with_length()

        # Native uses projectile travel direction as the side-offset basis and still emits the
        # trail quad even when origin≈head (degenerate impact frames).
        if type_id in (int(ProjectileTypeId.PISTOL), int(ProjectileTypeId.ASSAULT_RIFLE)):
            side_mul = 1.2
        elif type_id == int(ProjectileTypeId.GAUSS_GUN):
            side_mul = 1.1
        else:
            side_mul = 0.7
        half = 1.5 * side_mul * scale

        if dist > 1e-6:
            side = direction.perp_left()
        else:
            side = Vec2.from_angle(angle)

        side_offset = side * half
        p0 = start - side_offset
        p1 = start + side_offset
        p2 = end + side_offset
        p3 = end - side_offset

        # Native uses additive blending for bullet trails and sets color slots per projectile type.
        # Gauss has a distinct blue tint; most other bullet trails are neutral gray.
        if type_id == int(ProjectileTypeId.GAUSS_GUN):
            head_rgb = (51, 128, 255)  # (0.2, 0.5, 1.0)
        else:
            head_rgb = (128, 128, 128)  # (0.5, 0.5, 0.5)

        tail_rgb = (128, 128, 128)
        head = rl.Color(head_rgb[0], head_rgb[1], head_rgb[2], alpha)
        tail = rl.Color(tail_rgb[0], tail_rgb[1], tail_rgb[2], 0)
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        rl.rl_set_texture(self.bullet_trail_texture.id)
        rl.rl_begin(rd.RL_QUADS)
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
        return True

    def _draw_sharpshooter_laser_sight(
        self,
        *,
        camera: Vec2,
        view_scale: Vec2,
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

        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        rl.rl_set_texture(self.bullet_trail_texture.id)
        rl.rl_begin(rd.RL_QUADS)

        for player in players:
            if float(getattr(player, "health", 0.0)) <= 0.0:
                continue
            if not perk_active(player, PerkId.SHARPSHOOTER):
                continue
            player_pos = getattr(player, "pos", None)
            if not isinstance(player_pos, Vec2):
                continue

            aim_heading = float(getattr(player, "aim_heading", 0.0))
            aim_dir = Vec2.from_heading(aim_heading)
            start = player_pos + aim_dir * 15.0
            end = player_pos + aim_dir * 512.0

            start_screen = self._world_to_screen_with(start, camera=camera, view_scale=view_scale)
            end_screen = self._world_to_screen_with(end, camera=camera, view_scale=view_scale)
            segment = end_screen - start_screen
            direction, dist = segment.normalized_with_length()
            if dist <= 1e-3:
                continue

            thickness = max(1.0, 2.0 * scale)
            half = thickness * 0.5
            side_offset = direction.perp_left() * half
            p0 = start_screen - side_offset
            p1 = start_screen + side_offset
            p2 = end_screen + side_offset
            p3 = end_screen - side_offset

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

    def _draw_secondary_projectile(self, proj: SecondaryProjectile, *, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        proj_pos = proj.pos
        screen = self.world_to_screen(proj_pos)
        proj_type = int(proj.type_id)
        angle = float(proj.angle)

        ctx = SecondaryProjectileDrawCtx(
            renderer=self,
            proj=proj,
            proj_type=int(proj_type),
            screen_pos=screen,
            angle=float(angle),
            scale=float(scale),
            alpha=float(alpha),
        )
        if draw_secondary_projectile_from_registry(ctx):
            return
        rl.draw_circle(
            int(screen.x), int(screen.y), max(1.0, 4.0 * scale), rl.Color(200, 200, 220, int(200 * alpha + 0.5))
        )

    def _draw_particle_pool(self, *, camera: Vec2, view_scale: Vec2, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.particles_texture
        if texture is None:
            return

        particles = self.state.particles.entries
        if not any(entry.active for entry in particles):
            return

        scale = self._view_scale_avg(view_scale)

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

        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)

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
                screen = self._world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
                dst = rl.Rectangle(screen.x, screen.y, size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
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
            screen = self._world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rotation_deg = float(entry.spin) * _RAD_TO_DEG
            tint = RGBA(entry.scale_x, entry.scale_y, entry.scale_z, float(entry.age) * alpha).to_rl()
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
            screen = self._world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
            dst = rl.Rectangle(screen.x, screen.y, w, h)
            origin = rl.Vector2(w * 0.5, h * 0.5)
            tint = rl.Color(255, 255, 255, int(float(entry.age) * alpha_byte + 0.5))
            rl.draw_texture_pro(texture, src_style_8, dst, origin, 0.0, tint)

        rl.end_blend_mode()

    def _draw_sprite_effect_pool(
        self,
        *,
        camera: Vec2,
        view_scale: Vec2,
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

        atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.EXPLOSION_PUFF))
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
        scale = self._view_scale_avg(view_scale)

        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        for entry in effects:
            if not entry.active:
                continue
            size = float(entry.scale) * scale
            if size <= 0.0:
                continue
            screen = self._world_to_screen_with(entry.pos, camera=camera, view_scale=view_scale)
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rotation_deg = float(entry.rotation) * _RAD_TO_DEG
            tint = entry.color.scaled_alpha(alpha).to_rl()
            rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)
        rl.end_blend_mode()

    def _draw_effect_pool(self, *, camera: Vec2, view_scale: Vec2, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.particles_texture
        if texture is None:
            return

        effects = self.state.effects.entries
        if not any(entry.flags and entry.age >= 0.0 for entry in effects):
            return

        scale = self._view_scale_avg(view_scale)

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

            pos = getattr(entry, "pos", None)
            if not isinstance(pos, Vec2):
                return
            screen = self._world_to_screen_with(pos, camera=camera, view_scale=view_scale)

            half_w = float(getattr(entry, "half_width", 0.0))
            half_h = float(getattr(entry, "half_height", 0.0))
            local_scale = float(getattr(entry, "scale", 1.0))
            w = max(0.0, half_w * 2.0 * local_scale * scale)
            h = max(0.0, half_h * 2.0 * local_scale * scale)
            if w <= 0.0 or h <= 0.0:
                return

            rotation_deg = float(getattr(entry, "rotation", 0.0)) * _RAD_TO_DEG
            raw_color = getattr(entry, "color", None)
            if not isinstance(raw_color, RGBA):
                return
            tint = raw_color.scaled_alpha(alpha).to_rl()

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

    def draw(
        self,
        *,
        render_frame: RenderFrame | None = None,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
        self._render_frame = render_frame if render_frame is not None else self._world.build_render_frame()
        try:
            self._draw_with_active_frame(draw_aim_indicators=draw_aim_indicators, entity_alpha=entity_alpha)
        finally:
            self._render_frame = None

    def _draw_with_active_frame(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        entity_alpha = clamp(float(entity_alpha), 0.0, 1.0)
        clear_color = rl.Color(10, 10, 12, 255)
        screen_size = self._camera_screen_size()
        camera = self._clamp_camera(self.camera, screen_size)
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        scale_x = out_w / screen_size.x if screen_size.x > 0 else 1.0
        scale_y = out_h / screen_size.y if screen_size.y > 0 else 1.0
        view_scale = Vec2(scale_x, scale_y)
        if self.ground is None:
            rl.clear_background(clear_color)
        else:
            rl.clear_background(clear_color)
            self.ground.draw(camera, screen_w=screen_size.x, screen_h=screen_size.y)
        scale = self._view_scale_avg(view_scale)

        # World bounds for debug if terrain is missing.
        if self.ground is None:
            world_min = camera.mul_components(view_scale)
            world_max = (camera + Vec2(float(self.world_size), float(self.world_size))).mul_components(view_scale)
            rl.draw_rectangle_lines(
                int(world_min.x),
                int(world_min.y),
                int(world_max.x - world_min.x),
                int(world_max.y - world_min.y),
                rl.Color(40, 40, 55, 255),
            )

        if entity_alpha <= 1e-3:
            return

        alpha_test = True
        if self.ground is not None:
            alpha_test = bool(getattr(self.ground, "alpha_test", True))

        with _maybe_alpha_test(bool(alpha_test)):
            trooper_asset = CREATURE_ASSET.get(CreatureTypeId.TROOPER)
            trooper_texture = self.creature_textures.get(trooper_asset) if trooper_asset is not None else None
            particles_texture = self.particles_texture
            monster_vision = bool(self.players) and perk_active(self.players[0], PerkId.MONSTER_VISION)
            monster_vision_src: rl.Rectangle | None = None
            if monster_vision and particles_texture is not None:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.AURA))
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
            poison_src: rl.Rectangle | None = None
            if particles_texture is not None:
                # Native uses `effect_select_texture(0x10)` (EffectId.AURA) for creature overlays
                # (monster vision, shadow, poison aura).
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.AURA))
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        cell_w = float(particles_texture.width) / float(grid)
                        cell_h = float(particles_texture.height) / float(grid)
                        poison_src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )

            def draw_player(player: PlayerState) -> None:
                if trooper_texture is not None:
                    self._draw_player_trooper_sprite(
                        trooper_texture,
                        player,
                        camera=camera,
                        view_scale=view_scale,
                        scale=scale,
                        alpha=entity_alpha,
                    )
                    return

                screen = self._world_to_screen_with(player.pos, camera=camera, view_scale=view_scale)
                tint = rl.Color(90, 190, 120, int(255 * entity_alpha + 0.5))
                rl.draw_circle(int(screen.x), int(screen.y), max(1.0, 14.0 * scale), tint)

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
            creatures = [(idx, creature) for idx, creature in enumerate(self.creatures.entries) if creature.active]
            creatures.sort(
                key=lambda item: (creature_type_order.get(int(getattr(item[1], "type_id", -1)), 999), item[0])
            )
            for _idx, creature in creatures:
                screen = self._world_to_screen_with(creature.pos, camera=camera, view_scale=view_scale)
                hitbox_size = float(creature.hitbox_size)
                try:
                    type_id = CreatureTypeId(int(creature.type_id))
                except ValueError:
                    type_id = None
                asset = CREATURE_ASSET.get(type_id) if type_id is not None else None
                texture = self.creature_textures.get(asset) if asset is not None else None
                if (
                    particles_texture is not None
                    and poison_src is not None
                    and (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
                ):
                    fade = monster_vision_fade_alpha(hitbox_size)
                    poison_alpha = fade * entity_alpha
                    if poison_alpha > 1e-3:
                        size = 60.0 * scale
                        dst = rl.Rectangle(screen.x, screen.y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(255, 0, 0, int(clamp(poison_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.draw_texture_pro(particles_texture, poison_src, dst, origin, 0.0, tint)
                if monster_vision and particles_texture is not None and monster_vision_src is not None:
                    fade = monster_vision_fade_alpha(hitbox_size)
                    mv_alpha = fade * entity_alpha
                    if mv_alpha > 1e-3:
                        size = 90.0 * scale
                        dst = rl.Rectangle(screen.x, screen.y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(255, 255, 0, int(clamp(mv_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.draw_texture_pro(particles_texture, monster_vision_src, dst, origin, 0.0, tint)
                if texture is None:
                    tint = rl.Color(220, 90, 90, int(255 * entity_alpha + 0.5))
                    rl.draw_circle(int(screen.x), int(screen.y), max(1.0, creature.size * 0.5 * scale), tint)
                    continue

                info = CREATURE_ANIM.get(type_id) if type_id is not None else None
                if info is None:
                    continue

                tint_rgba = creature.tint

                # Energizer: tint "weak" creatures blue-ish while active.
                # Mirrors `creature_render_type` (0x00418b60) branch when
                # `_bonus_energizer_timer > 0` and `max_health < 500`.
                energizer_timer = float(self.state.bonuses.energizer)
                if energizer_timer > 0.0 and float(getattr(creature, "max_hp", 0.0)) < 500.0:
                    # Native clamps to 1.0, then blends towards (0.5, 0.5, 1.0, 1.0).
                    # Effect is full strength while timer >= 1 and fades out during the last second.
                    t = energizer_timer
                    if t >= 1.0:
                        t = 1.0
                    elif t < 0.0:
                        t = 0.0
                    tint_rgba = RGBA.lerp(tint_rgba, RGBA(0.5, 0.5, 1.0, 1.0), t)
                if hitbox_size < 0.0:
                    # Mirrors the main-pass alpha fade when hitbox_size ramps negative.
                    tint_rgba = tint_rgba.with_alpha(max(0.0, tint_rgba.a + hitbox_size * 0.1))
                tint = tint_rgba.scaled_alpha(entity_alpha).clamped().to_rl()

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
                    shadow_a = float(creature.tint.a) * 0.4
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
                    pos=creature.pos,
                    rotation_rad=float(creature.heading) - math.pi / 2.0,
                    scale=scale,
                    size_scale=size_scale,
                    tint=tint,
                    shadow=shadow,
                )

            freeze_timer = float(self.state.bonuses.freeze)
            if particles_texture is not None and freeze_timer > 0.0:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.FREEZE_SHATTER))
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
                            rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
                            for idx, creature in enumerate(self.creatures.entries):
                                if not creature.active:
                                    continue
                                size = float(creature.size) * scale
                                if size <= 1e-3:
                                    continue
                                creature_screen = self._world_to_screen_with(
                                    creature.pos,
                                    camera=camera,
                                    view_scale=view_scale,
                                )
                                dst = rl.Rectangle(creature_screen.x, creature_screen.y, size, size)
                                origin = rl.Vector2(size * 0.5, size * 0.5)
                                rotation_deg = (float(idx) * 0.01 + float(creature.heading)) * _RAD_TO_DEG
                                rl.draw_texture_pro(particles_texture, src, dst, origin, rotation_deg, tint)
                            rl.end_blend_mode()

            for player in self.players:
                if player.health > 0.0:
                    draw_player(player)

            self._draw_sharpshooter_laser_sight(
                camera=camera,
                view_scale=view_scale,
                scale=scale,
                alpha=entity_alpha,
            )

            for proj_index, proj in enumerate(self.state.projectiles.entries):
                if not proj.active:
                    continue
                self._draw_projectile(proj, proj_index=proj_index, scale=scale, alpha=entity_alpha)

            self._draw_particle_pool(camera=camera, view_scale=view_scale, alpha=entity_alpha)

            for proj in self.state.secondary_projectiles.entries:
                if not proj.active:
                    continue
                self._draw_secondary_projectile(proj, scale=scale, alpha=entity_alpha)

            self._draw_sprite_effect_pool(camera=camera, view_scale=view_scale, alpha=entity_alpha)
            self._draw_effect_pool(camera=camera, view_scale=view_scale, alpha=entity_alpha)
            self._draw_bonus_pickups(camera=camera, view_scale=view_scale, scale=scale, alpha=entity_alpha)
            self._draw_bonus_hover_labels(camera=camera, view_scale=view_scale, alpha=entity_alpha)

            if draw_aim_indicators and (not self.demo_mode_active):
                for player in self.players:
                    if player.health <= 0.0:
                        continue
                    aim = player.aim
                    dist = player.pos.distance_to(player.aim)
                    radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
                    aim_screen = self._world_to_screen_with(aim, camera=camera, view_scale=view_scale)
                    screen_radius = max(1.0, radius * scale)
                    self._draw_aim_circle(center=aim_screen, radius=screen_radius, alpha=entity_alpha)
                    reload_timer = float(getattr(player, "reload_timer", 0.0))
                    reload_max = float(getattr(player, "reload_timer_max", 0.0))
                    if reload_max > 1e-6 and reload_timer > 1e-6:
                        progress = reload_timer / reload_max
                        if progress > 0.0:
                            ms = int(progress * 60000.0)
                            self._draw_clock_gauge(
                                pos=Vec2(int(aim_screen.x), int(aim_screen.y)),
                                ms=ms,
                                scale=scale,
                                alpha=entity_alpha,
                            )

            self._draw_direction_arrows(
                camera=camera,
                view_scale=view_scale,
                scale=scale,
                alpha=entity_alpha,
            )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        return self._world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        safe_scale = Vec2(
            view_scale.x if view_scale.x > 0.0 else 1.0,
            view_scale.y if view_scale.y > 0.0 else 1.0,
        )
        return pos.div_components(safe_scale) - camera
