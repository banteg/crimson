from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import math
import os
from typing import Iterator
from typing import Iterable, Sequence

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
TERRAIN_DENSITY_SHIFT = 19
TERRAIN_ROTATION_MAX = 0x13A
TERRAIN_TILE_SIZE = 256
CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011


@contextmanager
def _blend_custom(src_factor: int, dst_factor: int, blend_equation: int) -> Iterator[None]:
    rl.begin_blend_mode(rl.BLEND_CUSTOM)
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    try:
        yield
    finally:
        rl.end_blend_mode()


@contextmanager
def _blend_custom_separate(
    src_rgb: int,
    dst_rgb: int,
    src_alpha: int,
    dst_alpha: int,
    eq_rgb: int,
    eq_alpha: int,
) -> Iterator[None]:
    rl.begin_blend_mode(rl.BLEND_CUSTOM_SEPARATE)
    rl.rl_set_blend_factors_separate(
        src_rgb, dst_rgb, src_alpha, dst_alpha, eq_rgb, eq_alpha
    )
    try:
        yield
    finally:
        rl.end_blend_mode()


class CrtRand:
    def __init__(self, seed: int | None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(4), "little")
        self._state = seed & 0xFFFFFFFF

    def rand(self) -> int:
        self._state = (self._state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        return (self._state >> 16) & 0x7FFF


@dataclass(slots=True)
class GroundDecal:
    texture: rl.Texture
    src: rl.Rectangle
    x: float
    y: float
    width: float
    height: float
    rotation_rad: float = 0.0
    tint: rl.Color = rl.WHITE
    centered: bool = True


@dataclass(slots=True)
class GroundCorpseDecal:
    bodyset_frame: int
    top_left_x: float
    top_left_y: float
    size: float
    rotation_rad: float
    tint: rl.Color = rl.WHITE


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
    terrain_filter: float = 1.0
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
        self.generate_partial(seed=seed, layers=3)

    def generate_partial(self, seed: int | None = None, *, layers: int) -> None:
        layers = max(0, min(int(layers), 3))
        self.create_render_target()
        if self.render_target is None:
            return
        rng = CrtRand(seed)
        self._set_stamp_filters(point=True)
        rl.begin_texture_mode(self.render_target)
        rl.clear_background(TERRAIN_CLEAR_COLOR)
        # Keep the ground RT alpha at 1.0 like the original exe (which typically uses
        # an XRGB render target). We still alpha-blend RGB, but preserve destination A.
        with _blend_custom_separate(
            rl.RL_SRC_ALPHA,
            rl.RL_ONE_MINUS_SRC_ALPHA,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        ):
            if layers >= 1:
                self._scatter_texture(
                    self.texture, TERRAIN_BASE_TINT, rng, TERRAIN_DENSITY_BASE
                )
            if layers >= 2 and self.overlay is not None:
                self._scatter_texture(
                    self.overlay, TERRAIN_OVERLAY_TINT, rng, TERRAIN_DENSITY_OVERLAY
                )
            if layers >= 3:
                # Original uses base texture for detail pass, not overlay
                self._scatter_texture(
                    self.texture, TERRAIN_DETAIL_TINT, rng, TERRAIN_DENSITY_DETAIL
                )
        rl.end_texture_mode()
        self._set_stamp_filters(point=False)

    def bake_decals(self, decals: Sequence[GroundDecal]) -> bool:
        if not decals:
            return False

        self.create_render_target()
        if self.render_target is None:
            return False

        inv_scale = 1.0 / self._normalized_texture_scale()
        textures = self._unique_textures([decal.texture for decal in decals])
        self._set_texture_filters(textures, point=True)

        rl.begin_texture_mode(self.render_target)
        with _blend_custom_separate(
            rl.RL_SRC_ALPHA,
            rl.RL_ONE_MINUS_SRC_ALPHA,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        ):
            for decal in decals:
                x = decal.x
                y = decal.y
                w = decal.width
                h = decal.height
                if decal.centered:
                    x -= w * 0.5
                    y -= h * 0.5
                x *= inv_scale
                y *= inv_scale
                w *= inv_scale
                h *= inv_scale
                dst = rl.Rectangle(x, y, w, h)
                origin = rl.Vector2(w * 0.5, h * 0.5)
                rl.draw_texture_pro(
                    decal.texture,
                    decal.src,
                    dst,
                    origin,
                    math.degrees(decal.rotation_rad),
                    decal.tint,
                )
        rl.end_texture_mode()

        self._set_texture_filters(textures, point=False)
        return True

    def bake_corpse_decals(
        self, bodyset_texture: rl.Texture, decals: Sequence[GroundCorpseDecal]
    ) -> bool:
        if not decals:
            return False

        self.create_render_target()
        if self.render_target is None:
            return False

        scale = self._normalized_texture_scale()
        inv_scale = 1.0 / scale
        offset = 2.0 * scale / float(self.width)
        self._set_texture_filters((bodyset_texture,), point=True)

        rl.begin_texture_mode(self.render_target)
        self._draw_corpse_shadow_pass(bodyset_texture, decals, inv_scale, offset)
        self._draw_corpse_color_pass(bodyset_texture, decals, inv_scale, offset)
        rl.end_texture_mode()

        self._set_texture_filters((bodyset_texture,), point=False)
        return True

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
        if self.terrain_filter == 2.0:
            rl.set_texture_filter(target.texture, rl.TEXTURE_FILTER_POINT)
        # Disable alpha blending when drawing terrain to screen - the render target's
        # alpha channel may be < 1.0 after stamp blending, but terrain should be opaque.
        with _blend_custom(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD):
            rl.draw_texture_pro(
                target.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE
            )
        if self.terrain_filter == 2.0:
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
        self._set_texture_filters(
            (self.texture, self.overlay, self.overlay_detail),
            point=point,
        )

    @staticmethod
    def _unique_textures(textures: Iterable[rl.Texture]) -> list[rl.Texture]:
        unique: list[rl.Texture] = []
        seen: set[int] = set()
        for texture in textures:
            texture_id = int(getattr(texture, "id", 0))
            if texture_id <= 0 or texture_id in seen:
                continue
            seen.add(texture_id)
            unique.append(texture)
        return unique

    @staticmethod
    def _set_texture_filters(textures: Iterable[rl.Texture | None], *, point: bool) -> None:
        mode = rl.TEXTURE_FILTER_POINT if point else rl.TEXTURE_FILTER_BILINEAR
        for texture in textures:
            if texture is None:
                continue
            if int(getattr(texture, "id", 0)) <= 0:
                continue
            rl.set_texture_filter(texture, mode)

    def _corpse_src(self, bodyset_texture: rl.Texture, frame: int) -> rl.Rectangle:
        frame = int(frame) & 0xF
        cell_w = float(bodyset_texture.width) * 0.25
        cell_h = float(bodyset_texture.height) * 0.25
        col = frame & 3
        row = frame >> 2
        return rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)

    def _draw_corpse_shadow_pass(
        self,
        bodyset_texture: rl.Texture,
        decals: Sequence[GroundCorpseDecal],
        inv_scale: float,
        offset: float,
    ) -> None:
        with _blend_custom_separate(
            rl.RL_ZERO,
            rl.RL_ONE_MINUS_SRC_ALPHA,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        ):
            for decal in decals:
                src = self._corpse_src(bodyset_texture, decal.bodyset_frame)
                size = decal.size * inv_scale * 1.064
                x = (decal.top_left_x - 0.5) * inv_scale - offset
                y = (decal.top_left_y - 0.5) * inv_scale - offset
                dst = rl.Rectangle(x, y, size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                tint = rl.Color(
                    decal.tint.r,
                    decal.tint.g,
                    decal.tint.b,
                    int(decal.tint.a * 0.5),
                )
                rl.draw_texture_pro(
                    bodyset_texture,
                    src,
                    dst,
                    origin,
                    math.degrees(decal.rotation_rad - (math.pi * 0.5)),
                    tint,
                )

    def _draw_corpse_color_pass(
        self,
        bodyset_texture: rl.Texture,
        decals: Sequence[GroundCorpseDecal],
        inv_scale: float,
        offset: float,
    ) -> None:
        with _blend_custom_separate(
            rl.RL_SRC_ALPHA,
            rl.RL_ONE_MINUS_SRC_ALPHA,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        ):
            for decal in decals:
                src = self._corpse_src(bodyset_texture, decal.bodyset_frame)
                size = decal.size * inv_scale
                x = decal.top_left_x * inv_scale - offset
                y = decal.top_left_y * inv_scale - offset
                dst = rl.Rectangle(x, y, size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                rl.draw_texture_pro(
                    bodyset_texture,
                    src,
                    dst,
                    origin,
                    math.degrees(decal.rotation_rad - (math.pi * 0.5)),
                    decal.tint,
                )
