from __future__ import annotations

import pyray as rl

from grim.geom import Vec2
from grim.math import clamp

from .constants import _RAD_TO_DEG
from .mixin_base import WorldRendererMixinBase


class WorldRendererOverlaysMixin(WorldRendererMixinBase):
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
        raw = self.config.hud_indicators
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
