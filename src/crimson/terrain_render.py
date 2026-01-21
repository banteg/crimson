from __future__ import annotations

from dataclasses import dataclass
import math
import os

import pyray as rl


TERRAIN_TEXTURE_SIZE = 1024
TERRAIN_PATCH_SIZE = 128.0
TERRAIN_PATCH_OVERSCAN = 64.0
TERRAIN_CLEAR_COLOR = rl.Color(63, 56, 25, 255)
TERRAIN_BASE_TINT = rl.Color(178, 178, 178, 230)
TERRAIN_OVERLAY_TINT = rl.Color(178, 178, 178, 230)
TERRAIN_DETAIL_TINT = rl.Color(178, 178, 178, 153)
TERRAIN_DENSITY_BASE = 800
TERRAIN_DENSITY_OVERLAY = 0x23
TERRAIN_DENSITY_DETAIL = 0x0F
TERRAIN_DENSITY_SHIFT = 13
TERRAIN_ROTATION_MAX = 0x13A
TERRAIN_TILE_SIZE = 256
CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011


class CrtRand:
    def __init__(self, seed: int | None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(4), "little")
        self._state = seed & 0xFFFFFFFF

    def rand(self) -> int:
        self._state = (self._state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        return (self._state >> 16) & 0x7FFF


@dataclass(slots=True)
class GroundRenderer:
    texture: rl.Texture
    width: int = TERRAIN_TEXTURE_SIZE
    height: int = TERRAIN_TEXTURE_SIZE
    texture_scale: float = 1.0
    texture_failed: bool = False
    screen_width: float | None = None
    screen_height: float | None = None
    overlay: rl.Texture | None = None
    overlay_detail: rl.Texture | None = None
    tile: rl.Texture | None = None
    display_filter: int = 2
    render_target: rl.RenderTexture | None = None

    def create_render_target(self) -> None:
        if self.texture_failed:
            if self.render_target is not None:
                rl.unload_render_texture(self.render_target)
                self.render_target = None
            return

        scale = self.texture_scale
        if scale < 0.5:
            scale = 0.5
        elif scale > 4.0:
            scale = 4.0
        self.texture_scale = scale

        render_w, render_h = self._render_target_size_for(scale)
        if self._ensure_render_target(render_w, render_h):
            return

        old_scale = scale
        self.texture_scale = scale + scale
        render_w, render_h = self._render_target_size_for(self.texture_scale)
        if self._ensure_render_target(render_w, render_h):
            return

        self.texture_failed = True
        self.texture_scale = old_scale
        if self.render_target is not None:
            rl.unload_render_texture(self.render_target)
            self.render_target = None

    def generate(self, seed: int | None = None) -> None:
        self.create_render_target()
        if self.render_target is None:
            return
        rng = CrtRand(seed)
        self._set_stamp_filters(point=True)
        rl.begin_texture_mode(self.render_target)
        rl.clear_background(TERRAIN_CLEAR_COLOR)
        self._scatter_texture(
            self.texture, TERRAIN_BASE_TINT, rng, TERRAIN_DENSITY_BASE
        )
        if self.overlay is not None:
            self._scatter_texture(
                self.overlay, TERRAIN_OVERLAY_TINT, rng, TERRAIN_DENSITY_OVERLAY
            )
        detail = self.overlay_detail or self.overlay
        if detail is not None:
            self._scatter_texture(
                detail, TERRAIN_DETAIL_TINT, rng, TERRAIN_DENSITY_DETAIL
            )
        rl.end_texture_mode()
        self._set_stamp_filters(point=False)

    def draw(self, camera_x: float, camera_y: float) -> None:
        if self.render_target is None:
            self._draw_fallback(camera_x, camera_y)
            return

        target = self.render_target
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w = float(self.screen_width or out_w)
        screen_h = float(self.screen_height or out_h)
        if screen_w > self.width:
            screen_w = float(self.width)
        if screen_h > self.height:
            screen_h = float(self.height)
        cam_x, cam_y = self._clamp_camera(camera_x, camera_y, screen_w, screen_h)
        u0 = -cam_x / float(self.width)
        v0 = -cam_y / float(self.height)
        u1 = u0 + screen_w / float(self.width)
        v1 = v0 + screen_h / float(self.height)
        src_x = u0 * float(target.texture.width)
        src_y = v0 * float(target.texture.height)
        src_w = (u1 - u0) * float(target.texture.width)
        src_h = (v1 - v0) * float(target.texture.height)
        src = rl.Rectangle(src_x, src_y, src_w, -src_h)
        dst = rl.Rectangle(0.0, 0.0, out_w, out_h)
        if self.display_filter == 1:
            rl.set_texture_filter(target.texture, rl.TEXTURE_FILTER_POINT)
        rl.draw_texture_pro(target.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        if self.display_filter == 1:
            rl.set_texture_filter(target.texture, rl.TEXTURE_FILTER_BILINEAR)

    def _scatter_texture(
        self,
        texture: rl.Texture,
        tint: rl.Color,
        rng: CrtRand,
        density: int,
    ) -> None:
        area = self.width * self.height
        count = (area * density) >> TERRAIN_DENSITY_SHIFT
        if count <= 0:
            return
        inv_scale = 1.0 / self._normalized_texture_scale()
        size = TERRAIN_PATCH_SIZE * inv_scale
        src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
        origin = rl.Vector2(size * 0.5, size * 0.5)
        span_w = self.width + int(TERRAIN_PATCH_OVERSCAN * 2)
        span_h = self.height + int(TERRAIN_PATCH_OVERSCAN * 2)
        for _ in range(count):
            angle = ((rng.rand() % TERRAIN_ROTATION_MAX) * 0.01) % math.tau
            x = ((rng.rand() % span_w) - TERRAIN_PATCH_OVERSCAN) * inv_scale
            y = ((rng.rand() % span_h) - TERRAIN_PATCH_OVERSCAN) * inv_scale
            dst = rl.Rectangle(float(x), float(y), size, size)
            rl.draw_texture_pro(
                texture, src, dst, origin, math.degrees(angle), tint
            )

    def _draw_fallback(self, camera_x: float, camera_y: float) -> None:
        tile = self.tile or self.texture
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w = float(self.screen_width or out_w)
        screen_h = float(self.screen_height or out_h)
        if screen_w > self.width:
            screen_w = float(self.width)
        if screen_h > self.height:
            screen_h = float(self.height)

        cam_x, cam_y = self._clamp_camera(camera_x, camera_y, screen_w, screen_h)
        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        tiles_x = (self.width >> 8) + 1
        tiles_y = (self.height >> 8) + 1
        src = rl.Rectangle(0.0, 0.0, float(tile.width), float(tile.height))
        origin = rl.Vector2(0.0, 0.0)
        for ty in range(tiles_y):
            for tx in range(tiles_x):
                x = (float(tx * TERRAIN_TILE_SIZE) + cam_x) * scale_x
                y = (float(ty * TERRAIN_TILE_SIZE) + cam_y) * scale_y
                dst = rl.Rectangle(
                    x,
                    y,
                    float(TERRAIN_TILE_SIZE) * scale_x,
                    float(TERRAIN_TILE_SIZE) * scale_y,
                )
                rl.draw_texture_pro(tile, src, dst, origin, 0.0, rl.WHITE)

    def _clamp_camera(
        self, camera_x: float, camera_y: float, screen_w: float, screen_h: float
    ) -> tuple[float, float]:
        min_x = screen_w - float(self.width)
        min_y = screen_h - float(self.height)
        if camera_x < min_x:
            camera_x = min_x
        if camera_x > -1.0:
            camera_x = -1.0
        if camera_y < min_y:
            camera_y = min_y
        if camera_y > -1.0:
            camera_y = -1.0
        return camera_x, camera_y

    def _ensure_render_target(self, render_w: int, render_h: int) -> bool:
        if self.render_target is not None:
            if (
                self.render_target.texture.width == render_w
                and self.render_target.texture.height == render_h
            ):
                return True
            rl.unload_render_texture(self.render_target)
            self.render_target = None

        try:
            candidate = rl.load_render_texture(render_w, render_h)
        except Exception:
            return False

        if not getattr(candidate, "id", 0) or not rl.is_render_texture_valid(candidate):
            if getattr(candidate, "id", 0):
                rl.unload_render_texture(candidate)
            return False
        if (
            getattr(getattr(candidate, "texture", None), "width", 0) <= 0
            or getattr(getattr(candidate, "texture", None), "height", 0) <= 0
        ):
            rl.unload_render_texture(candidate)
            return False

        self.render_target = candidate
        rl.set_texture_filter(self.render_target.texture, rl.TEXTURE_FILTER_BILINEAR)
        rl.set_texture_wrap(self.render_target.texture, rl.TEXTURE_WRAP_CLAMP)
        return True

    def _render_target_size_for(self, scale: float) -> tuple[int, int]:
        render_w = max(1, int(self.width / scale))
        render_h = max(1, int(self.height / scale))
        return render_w, render_h

    def _normalized_texture_scale(self) -> float:
        scale = self.texture_scale
        if scale < 0.5:
            scale = 0.5
        return scale

    def _set_stamp_filters(self, *, point: bool) -> None:
        mode = rl.TEXTURE_FILTER_POINT if point else rl.TEXTURE_FILTER_BILINEAR
        for texture in (self.texture, self.overlay, self.overlay_detail):
            if texture is None:
                continue
            rl.set_texture_filter(texture, mode)
