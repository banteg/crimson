from __future__ import annotations

import math

import pyray as rl

from grim.geom import Vec2
from grim.math import clamp
from grim.fonts.small import draw_small_text, measure_small_text_width

from ...bonuses import BONUS_BY_ID, BonusId
from ...bonuses.pool import bonus_find_aim_hover_entry, bonus_label_for_entry
from ...weapons import WEAPON_BY_ID
from .constants import _RAD_TO_DEG
from .mixin_base import WorldRendererMixinBase


class WorldRendererBonusesMixin(WorldRendererMixinBase):
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
            label = bonus_label_for_entry(entry, preserve_bugs=bool(self.state.preserve_bugs))
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
