from __future__ import annotations

import math
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import msgspec

from crimson.rng_caller_static import RngCallerStatic
from grim.raylib_api import rd, rl

from .geom import Vec2
from .rand import CrtRand
from .shaders import AlphaTestShader

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

_UNLOCK_RANDOM_TERRAIN_CALLERS: tuple[tuple[int, int, int], ...] = (
    (
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_X,
    ),
)

_EXPLICIT_TERRAIN_CALLERS: tuple[tuple[int, int, int], ...] = (
    (
        RngCallerStatic.TERRAIN_GENERATE_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_BASE_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_X,
    ),
)

# Grim2D enables alpha test globally with:
#   ALPHATESTENABLE=1, ALPHAFUNC=GREATER, ALPHAREF=4
# Static anchor: `grim_apply_render_state` @ 0x10004520.
#
# raylib does not expose fixed-function alpha test, so we emulate it with a tiny
# discard shader for stamping into the terrain render target. This shim is
# required for parity; if it fails to compile, rendering should stop rather than
# silently drift away from the native cutoff behavior.
@contextmanager
def _blend_custom(src_factor: int, dst_factor: int, blend_equation: int) -> Iterator[None]:
    # NOTE: raylib/rlgl tracks custom blend factors as state; some backends only
    # apply them when switching the blend mode. Set factors both before and
    # after BeginBlendMode() to ensure the current draw uses the intended values.
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM)
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    try:
        yield
    finally:
        rl.end_blend_mode()


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
    with _color_mask(write_alpha=False), _blend_custom(src_factor, dst_factor, blend_equation):
        yield


@contextmanager
def _texture_target(target: rl.RenderTexture) -> Iterator[None]:
    rl.begin_texture_mode(target)
    try:
        yield
    finally:
        rl.end_texture_mode()

class GroundDecal(msgspec.Struct):
    texture: rl.Texture
    src: rl.Rectangle
    pos: Vec2
    width: float
    height: float
    rotation_rad: float = 0.0
    tint: rl.Color = rl.WHITE


class GroundCorpseDecal(msgspec.Struct):
    bodyset_frame: int
    top_left: Vec2
    size: float
    rotation_rad: float
    tint: rl.Color = rl.WHITE


class GroundRenderer(msgspec.Struct):
    texture: rl.Texture
    overlay: rl.Texture
    overlay_detail: rl.Texture
    width: int = TERRAIN_TEXTURE_SIZE
    height: int = TERRAIN_TEXTURE_SIZE
    texture_scale: float = 1.0
    texture_failed: bool = False
    render_target: rl.RenderTexture | None = None
    alpha_test: AlphaTestShader = msgspec.field(default_factory=AlphaTestShader)
    _render_target_ready: bool = False
    _scheduled_seed: int | None = None
    _scheduled_generation_kind: str = "explicit"

    def close(self) -> None:
        if self.render_target is not None:
            rl.unload_render_texture(self.render_target)
            self.render_target = None
        self.alpha_test.close()
        self._render_target_ready = False
        self._scheduled_seed = None

    def generation_pending(self) -> bool:
        """True while a scheduled terrain generate is still pending."""
        return self._scheduled_seed is not None

    def render_target_ready(self) -> bool:
        """True when the terrain render target exists and is ready for drawing."""
        return self.render_target is not None and self._render_target_ready

    def process_pending(self) -> None:
        seed = self._scheduled_seed
        if seed is None:
            return
        generation_kind = self._scheduled_generation_kind
        self._generate_texture(seed=seed, generation_kind=generation_kind)
        self._scheduled_seed = None

    def _ensure_render_target(self) -> None:
        scale = min(max(self.texture_scale, 0.5), 4.0)
        self.texture_scale = scale

        render_w, render_h = self._render_target_size_for(scale)
        if self._load_render_target(render_w, render_h):
            self.texture_failed = False
            return

        self.texture_failed = True
        if self.render_target is not None:
            rl.unload_render_texture(self.render_target)
            self.render_target = None
        self._render_target_ready = False

    def schedule_generate(self, seed: int, *, generation_kind: str = "explicit") -> None:
        self._scheduled_seed = seed
        self._scheduled_generation_kind = str(generation_kind)

    def _generate_texture(self, seed: int, *, generation_kind: str) -> None:
        self._ensure_render_target()
        if self.render_target is None:
            return
        self._render_target_ready = False
        rng = CrtRand(seed)
        caller_sets = (
            _UNLOCK_RANDOM_TERRAIN_CALLERS
            if generation_kind == "unlock_random"
            else _EXPLICIT_TERRAIN_CALLERS
        )
        with _texture_target(self.render_target):
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
                self._scatter_texture(
                    self.texture,
                    TERRAIN_BASE_TINT,
                    rng,
                    TERRAIN_DENSITY_BASE,
                    callers=caller_sets[0],
                )
                self._scatter_texture(
                    self.overlay,
                    TERRAIN_OVERLAY_TINT,
                    rng,
                    TERRAIN_DENSITY_OVERLAY,
                    callers=caller_sets[1],
                )
                self._scatter_texture(
                    self.overlay_detail,
                    TERRAIN_DETAIL_TINT,
                    rng,
                    TERRAIN_DENSITY_DETAIL,
                    callers=caller_sets[2],
                )
        self._render_target_ready = True

    def bake_decals(self, decals: Sequence[GroundDecal]) -> bool:
        if not decals:
            return False

        if self.render_target is None or not self._render_target_ready:
            return False

        inv_scale = 1.0 / self._normalized_texture_scale()
        with _texture_target(self.render_target), self.alpha_test.scope(), _terrain_rt_blend(
            rd.RL_SRC_ALPHA,
            rd.RL_ONE_MINUS_SRC_ALPHA,
            rd.RL_FUNC_ADD,
        ):
            for decal in decals:
                w = decal.width * inv_scale
                h = decal.height * inv_scale
                dst = rl.Rectangle(decal.pos.x * inv_scale, decal.pos.y * inv_scale, w, h)
                origin = rl.Vector2(w * 0.5, h * 0.5)
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

        scale = self._normalized_texture_scale()
        inv_scale = 1.0 / scale
        offset = 2.0 * scale / float(self.width)
        # Intentional deviation: bilinear sampling reads better at modern output scales.
        with _texture_target(self.render_target), self.alpha_test.scope():
            self._draw_corpse_shadow_pass(bodyset_texture, decals, inv_scale, offset)
            self._draw_corpse_color_pass(bodyset_texture, decals, inv_scale, offset)

        self._render_target_ready = True
        return True

    def draw(self, camera: Vec2) -> None:
        out_w = max(1.0, float(rl.get_screen_width()))
        out_h = max(1.0, float(rl.get_screen_height()))
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
        src = rl.Rectangle(src_x, src_y, src_w, -src_h)
        dst = rl.Rectangle(0.0, 0.0, out_w, out_h)
        # Disable alpha blending when drawing terrain to screen - the render target's
        # alpha channel may be < 1.0 after stamp blending, but terrain should be opaque.
        with _blend_custom(rd.RL_ONE, rd.RL_ZERO, rd.RL_FUNC_ADD):
            rl.draw_texture_pro(target.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

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

    def _scatter_texture(
        self,
        texture: rl.Texture,
        tint: rl.Color,
        rng: CrtRand,
        density: int,
        *,
        callers: tuple[int, int, int],
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
        # The original exe uses `terrain_texture_width` for both axes. Terrain is
        # square (1024x1024) so this is equivalent, but keep it for parity.
        span_h = span_w
        for _ in range(count):
            angle = ((rng.rand_tagged(callers[0]) % TERRAIN_ROTATION_MAX) * 0.01) % math.tau
            # IMPORTANT: The exe consumes RNG as rotation, then Y, then X.
            y = ((rng.rand_tagged(callers[1]) % span_h) - TERRAIN_PATCH_OVERSCAN) * inv_scale
            x = ((rng.rand_tagged(callers[2]) % span_w) - TERRAIN_PATCH_OVERSCAN) * inv_scale
            # raylib's DrawTexturePro positions the quad by the *origin point*,
            # while the original engine uses x/y as the quad top-left.
            dst = rl.Rectangle(float(x + size * 0.5), float(y + size * 0.5), size, size)
            rl.draw_texture_pro(texture, src, dst, origin, math.degrees(angle), tint)

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
        screen_w = int(rl.get_screen_width())
        screen_h = int(rl.get_screen_height())
        render_w = int(rl.get_render_width())
        render_h = int(rl.get_render_height())
        if render_w == screen_w * 2 and render_h == screen_h * 2:
            return 2.0
        return 1.0

    def _render_target_size_for(self, scale: float) -> tuple[int, int]:
        pixel_scale = self._render_pixel_ratio()
        render_w = max(1, int((self.width * pixel_scale) / scale))
        render_h = max(1, int((self.height * pixel_scale) / scale))
        return render_w, render_h

    def _normalized_texture_scale(self) -> float:
        scale = self.texture_scale
        if scale < 0.5:
            scale = 0.5
        if self._render_pixel_ratio() == 2.0:
            scale *= 0.5
        return scale

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
                dst = rl.Rectangle(x + size * 0.5, y + size * 0.5, size, size)
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
                dst = rl.Rectangle(x + size * 0.5, y + size * 0.5, size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                rl.draw_texture_pro(
                    bodyset_texture,
                    src,
                    dst,
                    origin,
                    math.degrees(decal.rotation_rad - (math.pi * 0.5)),
                    decal.tint,
                )
