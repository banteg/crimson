from __future__ import annotations

import math
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import msgspec

from grim import canvas
from grim.raylib_api import rd, rl, rl_color, rl_rectangle, rl_vector2

from .blend import blend_custom, opaque_blend
from .geom import Vec2
from .shaders import AlphaTestShader
from .terrain_stamps import TerrainLayers, TerrainStampLayer
from .texture_mode import texture_mode

TERRAIN_TEXTURE_SIZE = 1024
TERRAIN_PATCH_SIZE = 128.0
TERRAIN_CLEAR_COLOR = rl_color(63, 56, 25, 255)
TERRAIN_BASE_TINT = rl_color(178, 178, 178, 230)
TERRAIN_OVERLAY_TINT = rl_color(178, 178, 178, 230)
TERRAIN_DETAIL_TINT = rl_color(178, 178, 178, 153)


@contextmanager
def _color_mask(*, write_alpha: bool) -> Iterator[None]:
    rl.rl_color_mask(True, True, True, bool(write_alpha))
    try:
        yield
    finally:
        rl.rl_color_mask(True, True, True, True)


@contextmanager
def _terrain_rt_blend(
    src_factor: int,
    dst_factor: int,
    blend_equation: int,
) -> Iterator[None]:
    with _color_mask(write_alpha=False), blend_custom(src_factor, dst_factor, blend_equation):
        yield


class GroundDecal(msgspec.Struct):
    texture: rl.Texture
    src: rl.Rectangle
    pos: Vec2
    width: float
    height: float
    rotation_rad: float = 0.0
    # `rl.WHITE` is a plain tuple in pyray; the draws read `.r` / `.a`.
    tint: rl.Color = msgspec.field(default_factory=lambda: rl_color(255, 255, 255, 255))


class GroundCorpseDecal(msgspec.Struct):
    bodyset_frame: int
    top_left: Vec2
    size: float
    rotation_rad: float
    tint: rl.Color = msgspec.field(default_factory=lambda: rl_color(255, 255, 255, 255))


class GroundRenderer(msgspec.Struct):
    texture: rl.Texture
    overlay: rl.Texture
    overlay_detail: rl.Texture
    width: int = TERRAIN_TEXTURE_SIZE
    height: int = TERRAIN_TEXTURE_SIZE
    texture_failed: bool = False
    render_target: rl.RenderTexture | None = None
    alpha_test: AlphaTestShader = msgspec.field(default_factory=AlphaTestShader)
    _render_target_ready: bool = False
    _scheduled_layers: TerrainLayers | None = None
    _scheduled_texture_scale: float = 1.0

    def close(self) -> None:
        if self.render_target is not None:
            rl.unload_render_texture(self.render_target)
            self.render_target = None
        self.alpha_test.close()
        self._render_target_ready = False
        self._scheduled_layers = None

    def render_target_ready(self) -> bool:
        """True when the terrain render target exists and is ready for drawing."""
        return self.render_target is not None and self._render_target_ready

    def process_pending(self) -> None:
        layers = self._scheduled_layers
        if layers is None:
            return
        self._generate_texture(layers, self._scheduled_texture_scale)
        self._scheduled_layers = None

    def _ensure_render_target(self, texture_scale: float) -> None:
        scale = min(max(texture_scale, 0.5), 4.0)
        render_w, render_h = self._render_target_size_for(scale)
        if self._load_render_target(render_w, render_h):
            self.texture_failed = False
            return

        self.texture_failed = True
        if self.render_target is not None:
            rl.unload_render_texture(self.render_target)
            self.render_target = None
        self._render_target_ready = False

    def schedule_stamps(self, layers: TerrainLayers, *, texture_scale: float) -> None:
        """Queue drawing generated terrain stamps; the target is (re)built on the next `process_pending`.

        `texture_scale` only sizes the target. Bakes read their scale back from the allocated target.
        """
        self._scheduled_layers = layers
        self._scheduled_texture_scale = texture_scale

    def _generate_texture(self, layers: TerrainLayers, texture_scale: float) -> None:
        self._ensure_render_target(texture_scale)
        if self.render_target is None:
            return
        self._render_target_ready = False
        with texture_mode(self.render_target):
            rl.clear_background(TERRAIN_CLEAR_COLOR)
            # Intentional rewrite deviation: the classic game appears to point-sample
            # terrain stamps while rotating them into the RT, but bilinear sampling
            # reads better in the port and still stays within current fixture tolerances.
            # Keep the ground RT alpha opaque like the original exe's XRGB-style RT.
            # The port does that by masking out alpha writes while stamping.
            with self.alpha_test.scope(), _terrain_rt_blend(
                rd.RL_SRC_ALPHA,
                rd.RL_ONE_MINUS_SRC_ALPHA,
                rd.RL_FUNC_ADD,
            ):
                self._draw_stamps(self.texture, TERRAIN_BASE_TINT, layers.base)
                self._draw_stamps(self.overlay, TERRAIN_OVERLAY_TINT, layers.overlay)
                self._draw_stamps(self.overlay_detail, TERRAIN_DETAIL_TINT, layers.detail)
        self._render_target_ready = True

    def bake_decals(self, decals: Sequence[GroundDecal]) -> bool:
        if not decals:
            return False

        if self.render_target is None or not self._render_target_ready:
            return False

        inv_scale = 1.0 / self._units_per_target_pixel()
        with texture_mode(self.render_target), self.alpha_test.scope(), _terrain_rt_blend(
            rd.RL_SRC_ALPHA,
            rd.RL_ONE_MINUS_SRC_ALPHA,
            rd.RL_FUNC_ADD,
        ):
            for decal in decals:
                w = decal.width * inv_scale
                h = decal.height * inv_scale
                dst = rl_rectangle(decal.pos.x * inv_scale, decal.pos.y * inv_scale, w, h)
                origin = rl_vector2(w * 0.5, h * 0.5)
                rl.draw_texture_pro(
                    decal.texture,
                    decal.src,
                    dst,
                    origin,
                    math.degrees(decal.rotation_rad),
                    decal.tint,
                )

        self._render_target_ready = True
        return True

    def bake_corpse_decals(
        self,
        bodyset_texture: rl.Texture,
        decals: Sequence[GroundCorpseDecal],
    ) -> bool:
        if not decals:
            return False

        if self.render_target is None or not self._render_target_ready:
            return False

        scale = self._units_per_target_pixel()
        inv_scale = 1.0 / scale
        offset = 2.0 * scale / float(self.width)
        # Intentional deviation: bilinear sampling reads better at modern output scales.
        with texture_mode(self.render_target), self.alpha_test.scope():
            self._draw_corpse_shadow_pass(bodyset_texture, decals, inv_scale, offset)
            self._draw_corpse_color_pass(bodyset_texture, decals, inv_scale, offset)

        self._render_target_ready = True
        return True

    def draw(self, camera: Vec2) -> None:
        out_w = max(1.0, float(canvas.width()))
        out_h = max(1.0, float(canvas.height()))
        screen_w, screen_h = self._fit_view_window(out_w, out_h)
        cam = self._clamp_camera(camera, screen_w, screen_h)
        self._draw_view(cam, screen_w=screen_w, screen_h=screen_h, out_w=out_w, out_h=out_h)

    def draw_view(
        self,
        camera: Vec2,
        *,
        screen_w: float,
        screen_h: float,
        out_w: float,
        out_h: float,
    ) -> None:
        self._draw_view(
            camera,
            screen_w=max(1.0, float(screen_w)),
            screen_h=max(1.0, float(screen_h)),
            out_w=max(1.0, float(out_w)),
            out_h=max(1.0, float(out_h)),
        )

    def _draw_view(
        self,
        camera: Vec2,
        *,
        screen_w: float,
        screen_h: float,
        out_w: float,
        out_h: float,
    ) -> None:
        if self.render_target is None or not self._render_target_ready:
            rl.draw_rectangle(0, 0, int(out_w + 0.5), int(out_h + 0.5), TERRAIN_CLEAR_COLOR)
            return

        target = self.render_target
        u0 = -camera.x / float(self.width)
        v0 = -camera.y / float(self.height)
        u1 = u0 + screen_w / float(self.width)
        v1 = v0 + screen_h / float(self.height)
        src_x = u0 * float(target.texture.width)
        # Render textures are vertically flipped in raylib, so adjust the source
        # rectangle to sample the correct world-space slice before flipping.
        src_y = (1.0 - v1) * float(target.texture.height)
        src_w = (u1 - u0) * float(target.texture.width)
        src_h = (v1 - v0) * float(target.texture.height)
        src = rl_rectangle(src_x, src_y, src_w, -src_h)
        dst = rl_rectangle(0.0, 0.0, out_w, out_h)
        # Disable alpha blending when drawing terrain to screen - the render target's
        # alpha channel may be < 1.0 after stamp blending, but terrain should be opaque.
        with opaque_blend():
            rl.draw_texture_pro(target.texture, src, dst, rl_vector2(0.0, 0.0), 0.0, rl.WHITE)

    def _fit_view_window(self, screen_w: float, screen_h: float) -> tuple[float, float]:
        """
        Convert output dimensions into a world-space camera window.

        Keep a uniform pixel scale and never request a camera window larger than
        the terrain dimensions. This avoids non-uniform stretch on widescreen
        outputs where only one axis exceeds world size.
        """

        world_w = float(self.width)
        world_h = float(self.height)
        if world_w <= 0.0 or world_h <= 0.0:
            return max(1.0, float(screen_w)), max(1.0, float(screen_h))

        out_w = max(1.0, float(screen_w))
        out_h = max(1.0, float(screen_h))
        scale = max(out_w / world_w, out_h / world_h, 1.0)
        view_w = min(world_w, out_w / scale)
        view_h = min(world_h, out_h / scale)
        return view_w, view_h

    def _draw_stamps(self, texture: rl.Texture, tint: rl.Color, stamps: TerrainStampLayer) -> None:
        inv_scale = 1.0 / self._units_per_target_pixel()
        size = TERRAIN_PATCH_SIZE * inv_scale
        src = rl_rectangle(0.0, 0.0, float(texture.width), float(texture.height))
        origin = rl_vector2(size * 0.5, size * 0.5)
        for rotation, x, y in stamps:
            # `position *= inv_scale` on the native pre-scale top-left.
            x *= inv_scale
            y *= inv_scale
            # raylib's DrawTexturePro positions the quad by the *origin point*,
            # while the original engine uses x/y as the quad top-left.
            dst = rl_rectangle(float(x + size * 0.5), float(y + size * 0.5), size, size)
            rl.draw_texture_pro(texture, src, dst, origin, math.degrees(rotation), tint)

    def _clamp_camera(self, camera: Vec2, screen_w: float, screen_h: float) -> Vec2:
        min_x = screen_w - float(self.width)
        min_y = screen_h - float(self.height)
        return Vec2(
            max(min(camera.x, -1.0), min_x),
            max(min(camera.y, -1.0), min_y),
        )

    def _load_render_target(self, render_w: int, render_h: int) -> bool:
        if self.render_target is not None:
            if self.render_target.texture.width == render_w and self.render_target.texture.height == render_h:
                return True
            rl.unload_render_texture(self.render_target)
            self.render_target = None
            self._render_target_ready = False

        candidate = rl.load_render_texture(render_w, render_h)
        if candidate.id <= 0 or candidate.texture.width <= 0 or candidate.texture.height <= 0:
            rl.unload_render_texture(candidate)
            return False
        # raylib's IsRenderTextureValid() only checks ids and dimensions; use the
        # rlgl completeness check so incomplete FBO attachments fail immediately.
        if not rl.rl_framebuffer_complete(candidate.id):
            rl.unload_render_texture(candidate)
            return False

        try:
            rl.set_texture_filter(candidate.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
            rl.set_texture_wrap(candidate.texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
        except Exception:
            rl.unload_render_texture(candidate)
            raise
        self.render_target = candidate
        self._render_target_ready = False
        return True

    def _render_pixel_ratio(self) -> float:
        # Window DPI, not render/screen size: raylib 6 reports the bound FBO's size
        # from GetRender*() inside texture mode, where terrain stamping happens.
        dpi = rl.get_window_scale_dpi()
        if dpi.x == 2.0 and dpi.y == 2.0:
            return 2.0
        return 1.0

    def _render_target_size_for(self, scale: float) -> tuple[int, int]:
        pixel_scale = self._render_pixel_ratio()
        render_w = max(1, int((self.width * pixel_scale) / scale))
        render_h = max(1, int((self.height * pixel_scale) / scale))
        return render_w, render_h

    def _units_per_target_pixel(self) -> float:
        # The ground target survives window/monitor DPI changes. Its allocated
        # dimensions, rather than the current window DPI, define bake coordinates.
        target = self.render_target
        assert target is not None
        return float(self.width) / float(target.texture.width)

    def _corpse_src(self, bodyset_texture: rl.Texture, frame: int) -> rl.Rectangle:
        frame = int(frame) & 0xF
        cell_w = float(bodyset_texture.width) * 0.25
        cell_h = float(bodyset_texture.height) * 0.25
        col = frame & 3
        row = frame >> 2
        return rl_rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)

    def _draw_corpse_shadow_pass(
        self,
        bodyset_texture: rl.Texture,
        decals: Sequence[GroundCorpseDecal],
        inv_scale: float,
        offset: float,
    ) -> None:
        with _terrain_rt_blend(
            rd.RL_ZERO,
            rd.RL_ONE_MINUS_SRC_ALPHA,
            rd.RL_FUNC_ADD,
        ):
            for decal in decals:
                src = self._corpse_src(bodyset_texture, decal.bodyset_frame)
                size = decal.size * inv_scale * 1.064
                x = (decal.top_left.x - 0.5) * inv_scale - offset
                y = (decal.top_left.y - 0.5) * inv_scale - offset
                dst = rl_rectangle(x + size * 0.5, y + size * 0.5, size, size)
                origin = rl_vector2(size * 0.5, size * 0.5)
                tint = rl_color(
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
        with _terrain_rt_blend(
            rd.RL_SRC_ALPHA,
            rd.RL_ONE_MINUS_SRC_ALPHA,
            rd.RL_FUNC_ADD,
        ):
            for decal in decals:
                src = self._corpse_src(bodyset_texture, decal.bodyset_frame)
                size = decal.size * inv_scale
                x = decal.top_left.x * inv_scale - offset
                y = decal.top_left.y * inv_scale - offset
                dst = rl_rectangle(x + size * 0.5, y + size * 0.5, size, size)
                origin = rl_vector2(size * 0.5, size * 0.5)
                rl.draw_texture_pro(
                    bodyset_texture,
                    src,
                    dst,
                    origin,
                    math.degrees(decal.rotation_rad - (math.pi * 0.5)),
                    decal.tint,
                )
