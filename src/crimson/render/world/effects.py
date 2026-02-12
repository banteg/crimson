from __future__ import annotations

import math

import pyray as rl

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp

from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from .constants import _RAD_TO_DEG
from .mixin_base import WorldRendererMixinBase


class WorldRendererEffectsMixin(WorldRendererMixinBase):
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
