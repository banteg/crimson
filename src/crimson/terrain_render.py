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
TERRAIN_DENSITY_DIV = 0x80000
TERRAIN_ROTATION_MAX = 0x13A
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
    screen_width: float | None = None
    screen_height: float | None = None
    overlay: rl.Texture | None = None
    overlay_detail: rl.Texture | None = None
    render_target: rl.RenderTexture | None = None

    def create_render_target(self) -> None:
        render_w, render_h = self._render_target_size()
        if self.render_target is not None:
            if (
                self.render_target.texture.width == render_w
                and self.render_target.texture.height == render_h
            ):
                return
            rl.unload_render_texture(self.render_target)
        self.render_target = rl.load_render_texture(render_w, render_h)
        rl.set_texture_filter(self.render_target.texture, rl.TEXTURE_FILTER_BILINEAR)
        rl.set_texture_wrap(self.render_target.texture, rl.TEXTURE_WRAP_CLAMP)

    def generate(self, seed: int | None = None) -> None:
        self.create_render_target()
        if self.render_target is None:
            return
        rng = CrtRand(seed)
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

    def draw(self, camera_x: float, camera_y: float) -> None:
        target = self.render_target
        if target is None:
            return
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
        src = rl.Rectangle(src_x, src_y + src_h, src_w, -src_h)
        dst = rl.Rectangle(0.0, 0.0, out_w, out_h)
        rl.draw_texture_pro(target.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

    def _scatter_texture(
        self,
        texture: rl.Texture,
        tint: rl.Color,
        rng: CrtRand,
        density: int,
    ) -> None:
        area = self.width * self.height
        count = (area * density) // TERRAIN_DENSITY_DIV
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

    def _clamp_camera(
        self, camera_x: float, camera_y: float, screen_w: float, screen_h: float
    ) -> tuple[float, float]:
        min_x = screen_w - float(self.width)
        min_y = screen_h - float(self.height)
        if camera_x < min_x:
            camera_x = min_x
        if camera_x > 0.0:
            camera_x = 0.0
        if camera_y < min_y:
            camera_y = min_y
        if camera_y > 0.0:
            camera_y = 0.0
        return camera_x, camera_y

    def _render_target_size(self) -> tuple[int, int]:
        scale = self._normalized_texture_scale()
        render_w = max(1, int(round(self.width / scale)))
        render_h = max(1, int(round(self.height / scale)))
        return render_w, render_h

    def _normalized_texture_scale(self) -> float:
        scale = self.texture_scale
        if scale < 0.5:
            scale = 0.5
        elif scale > 4.0:
            scale = 4.0
        return scale
