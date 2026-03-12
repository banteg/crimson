from __future__ import annotations

import math
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager

import msgspec

from grim.raylib_api import rd, rl

from .geom import Vec2
from .rand import CrtRand

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


_ALPHA_TEST_REF_U8 = 4
_ALPHA_TEST_REF_F32 = float(_ALPHA_TEST_REF_U8) / 255.0

# Grim2D enables alpha test globally with:
#   ALPHATESTENABLE=1, ALPHAFUNC=GREATER, ALPHAREF=4
# See: analysis/ghidra/raw/grim.dll_decompiled.c (FUN_10004520).
#
# raylib does not expose fixed-function alpha test, so we emulate it with a tiny
# discard shader for stamping into the terrain render target.
_ALPHA_TEST_SHADER: rl.Shader | None = None
_ALPHA_TEST_SHADER_TRIED = False

_ALPHA_TEST_VS_330 = r"""
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;

out vec2 fragTexCoord;
out vec4 fragColor;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

_ALPHA_TEST_FS_330 = rf"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;

out vec4 finalColor;

void main() {{
    vec4 texel = texture(texture0, fragTexCoord) * fragColor * colDiffuse;
    if (texel.a <= {_ALPHA_TEST_REF_F32:.10f}) discard;
    finalColor = texel;
}}
"""


def _get_alpha_test_shader() -> rl.Shader | None:
    global _ALPHA_TEST_SHADER, _ALPHA_TEST_SHADER_TRIED
    if _ALPHA_TEST_SHADER_TRIED:
        if _ALPHA_TEST_SHADER is not None and _ALPHA_TEST_SHADER.id > 0:
            return _ALPHA_TEST_SHADER
        return None

    _ALPHA_TEST_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_ALPHA_TEST_VS_330, _ALPHA_TEST_FS_330)
    except (RuntimeError, OSError, ValueError):
        _ALPHA_TEST_SHADER = None
        return None

    if shader.id <= 0:
        _ALPHA_TEST_SHADER = None
        return None

    _ALPHA_TEST_SHADER = shader
    return _ALPHA_TEST_SHADER


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
def _blend_custom_separate(
    src_rgb: int,
    dst_rgb: int,
    src_alpha: int,
    dst_alpha: int,
    eq_rgb: int,
    eq_alpha: int,
) -> Iterator[None]:
    # NOTE: raylib/rlgl tracks custom blend factors as state; some backends only
    # apply them when switching the blend mode. Set factors both before and
    # after BeginBlendMode() to ensure the current draw uses the intended values.
    rl.rl_set_blend_factors_separate(src_rgb, dst_rgb, src_alpha, dst_alpha, eq_rgb, eq_alpha)
    rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM_SEPARATE)
    rl.rl_set_blend_factors_separate(src_rgb, dst_rgb, src_alpha, dst_alpha, eq_rgb, eq_alpha)
    try:
        yield
    finally:
        rl.end_blend_mode()


@contextmanager
def _maybe_alpha_test(enabled: bool) -> Iterator[None]:
    if not enabled:
        yield
        return
    shader = _get_alpha_test_shader()
    if shader is None:
        yield
        return
    rl.begin_shader_mode(shader)
    try:
        yield
    finally:
        rl.end_shader_mode()


def _unique_valid_textures(textures: Iterable[rl.Texture | None]) -> tuple[rl.Texture, ...]:
    unique: list[rl.Texture] = []
    seen: set[int] = set()
    for texture in textures:
        if texture is None or texture.id <= 0:
            continue
        texture_id = int(texture.id)
        if texture_id in seen:
            continue
        seen.add(texture_id)
        unique.append(texture)
    return tuple(unique)


@contextmanager
def _temporary_point_filters(textures: Iterable[rl.Texture | None]) -> Iterator[None]:
    unique = _unique_valid_textures(textures)
    if not unique:
        yield
        return
    for texture in unique:
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
    try:
        yield
    finally:
        for texture in unique:
            rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)


class GroundDecal(msgspec.Struct):
    texture: rl.Texture
    src: rl.Rectangle
    pos: Vec2
    width: float
    height: float
    rotation_rad: float = 0.0
    tint: rl.Color = rl.WHITE
    centered: bool = True


class GroundCorpseDecal(msgspec.Struct):
    bodyset_frame: int
    top_left: Vec2
    size: float
    rotation_rad: float
    tint: rl.Color = rl.WHITE


class GroundRenderer(msgspec.Struct):
    texture: rl.Texture
    width: int = TERRAIN_TEXTURE_SIZE
    height: int = TERRAIN_TEXTURE_SIZE
    texture_scale: float = 1.0
    alpha_test: bool = True
    debug_log_stamps: bool = False
    texture_failed: bool = False
    screen_width: float | None = None
    screen_height: float | None = None
    overlay: rl.Texture | None = None
    overlay_detail: rl.Texture | None = None
    terrain_filter: float = 1.0
    render_target: rl.RenderTexture | None = None
    _debug_stamp_log: list[dict[str, object]] = msgspec.field(default_factory=list)
    _render_target_ready: bool = False
    _pending_generate: bool = False
    _pending_generate_seed: int | None = None
    _pending_generate_layers: int = 3
    _render_target_warmup_passes: int = 0

    def debug_clear_stamp_log(self) -> None:
        self._debug_stamp_log.clear()

    def debug_stamp_log(self) -> tuple[dict[str, object], ...]:
        return tuple(self._debug_stamp_log)

    def generation_pending(self) -> bool:
        """True while a scheduled terrain generate is still pending."""
        return self._pending_generate

    def render_target_ready(self) -> bool:
        """True when the terrain render target exists and is ready for drawing."""
        return self.render_target is not None and self._render_target_ready

    def _debug_stamp(self, kind: str, **payload: object) -> None:
        if not self.debug_log_stamps:
            return
        self._debug_stamp_log.append({"kind": kind, **payload})
        if len(self._debug_stamp_log) > 96:
            del self._debug_stamp_log[:32]

    def process_pending(self) -> None:
        # Bound the amount of work per tick. Typical warmup sequence:
        #   1) create RT
        #   2) first fill (may be black/uninitialized on some platforms)
        #   3) warmup retry fill
        steps = 0
        while self._pending_generate and steps < 4:
            steps += 1
            if self.render_target is None:
                self.create_render_target()
                continue

            seed = self._pending_generate_seed
            layers = self._pending_generate_layers
            self._pending_generate = False
            self.generate_partial(seed=seed, layers=layers)
            if self.render_target is None and not self.texture_failed:
                self._pending_generate = True
                continue

            if self._render_target_warmup_passes > 0:
                self._render_target_warmup_passes -= 1
                # On some platforms/drivers the first draw into a new RT can come out as
                # black/uninitialized (all-zero). Retry once before marking it ready.
                self._render_target_ready = False
                self._pending_generate = True
                continue

    def create_render_target(self) -> None:
        if self.texture_failed:
            if self.render_target is not None:
                rl.unload_render_texture(self.render_target)
                self.render_target = None
            self._render_target_ready = False
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
        self._render_target_ready = False

    def generate(self, seed: int | None = None) -> None:
        self.generate_partial(seed=seed, layers=3)

    def schedule_generate(self, seed: int | None = None, *, layers: int = 3) -> None:
        self._pending_generate_seed = seed
        self._pending_generate_layers = max(0, min(layers, 3))
        self._pending_generate = True

    def generate_partial(self, seed: int | None = None, *, layers: int) -> None:
        layers = max(0, min(layers, 3))
        detail_texture = self.overlay_detail or self.texture
        self.create_render_target()
        if self.render_target is None:
            return
        rng = CrtRand(seed)
        self._set_stamp_filters(point=True)
        rl.begin_texture_mode(self.render_target)
        rl.clear_background(TERRAIN_CLEAR_COLOR)
        # Keep the ground RT alpha at 1.0 like the original exe (which typically uses
        # an XRGB render target). We still alpha-blend RGB, but preserve destination A.
        with _maybe_alpha_test(self.alpha_test):
            with _blend_custom_separate(
                rd.RL_SRC_ALPHA,
                rd.RL_ONE_MINUS_SRC_ALPHA,
                rd.RL_ZERO,
                rd.RL_ONE,
                rd.RL_FUNC_ADD,
                rd.RL_FUNC_ADD,
            ):
                if layers >= 1:
                    self._scatter_texture(self.texture, TERRAIN_BASE_TINT, rng, TERRAIN_DENSITY_BASE)
                if layers >= 2 and self.overlay is not None:
                    self._scatter_texture(self.overlay, TERRAIN_OVERLAY_TINT, rng, TERRAIN_DENSITY_OVERLAY)
                if layers >= 3:
                    self._scatter_texture(detail_texture, TERRAIN_DETAIL_TINT, rng, TERRAIN_DENSITY_DETAIL)
        rl.end_texture_mode()
        self._set_stamp_filters(point=False)
        self._render_target_ready = True

    def bake_decals(self, decals: Sequence[GroundDecal]) -> bool:
        if not decals:
            return False

        self.create_render_target()
        if self.render_target is None:
            return False

        if self.debug_log_stamps:
            head = decals[0]
            self._debug_stamp(
                "bake_decals",
                count=len(decals),
                pos0=head.pos.to_dict(),
                rot0=float(head.rotation_rad),
            )

        inv_scale = 1.0 / self._normalized_texture_scale()
        rl.begin_texture_mode(self.render_target)
        with _temporary_point_filters(decal.texture for decal in decals):
            with _maybe_alpha_test(self.alpha_test):
                with _blend_custom_separate(
                    rd.RL_SRC_ALPHA,
                    rd.RL_ONE_MINUS_SRC_ALPHA,
                    rd.RL_ZERO,
                    rd.RL_ONE,
                    rd.RL_FUNC_ADD,
                    rd.RL_FUNC_ADD,
                ):
                    for decal in decals:
                        w = decal.width
                        h = decal.height
                        if decal.centered:
                            pivot_x = decal.pos.x
                            pivot_y = decal.pos.y
                        else:
                            pivot_x = decal.pos.x + w * 0.5
                            pivot_y = decal.pos.y + h * 0.5
                        pivot_x *= inv_scale
                        pivot_y *= inv_scale
                        w *= inv_scale
                        h *= inv_scale
                        dst = rl.Rectangle(pivot_x, pivot_y, w, h)
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

        self._render_target_ready = True
        return True

    def bake_corpse_decals(
        self,
        bodyset_texture: rl.Texture,
        decals: Sequence[GroundCorpseDecal],
        *,
        shadow: bool = True,
    ) -> bool:
        if not decals:
            return False

        self.create_render_target()
        if self.render_target is None:
            return False

        if self.debug_log_stamps:
            head = decals[0]
            self._debug_stamp(
                "bake_corpse_decals",
                shadow=shadow,
                count=len(decals),
                frame0=int(head.bodyset_frame),
                top_left0=head.top_left.to_dict(),
                size0=float(head.size),
                rot0=float(head.rotation_rad),
            )

        scale = self._normalized_texture_scale()
        inv_scale = 1.0 / scale
        offset = 2.0 * scale / float(self.width)
        rl.begin_texture_mode(self.render_target)
        with _temporary_point_filters((bodyset_texture,)):
            with _maybe_alpha_test(self.alpha_test):
                if shadow:
                    if self.debug_log_stamps:
                        self._debug_stamp("corpse_shadow_pass", draws=len(decals))
                    self._draw_corpse_shadow_pass(bodyset_texture, decals, inv_scale, offset)
                if self.debug_log_stamps:
                    self._debug_stamp("corpse_color_pass", draws=len(decals))
                self._draw_corpse_color_pass(bodyset_texture, decals, inv_scale, offset)
        rl.end_texture_mode()

        self._render_target_ready = True
        return True

    def draw(
        self,
        camera: Vec2,
        *,
        screen_w: float | None = None,
        screen_h: float | None = None,
        out_w: float | None = None,
        out_h: float | None = None,
    ) -> None:
        if out_w is None:
            out_w = float(rl.get_screen_width())
        else:
            out_w = float(out_w)
        if out_h is None:
            out_h = float(rl.get_screen_height())
        else:
            out_h = float(out_h)
        if out_w <= 0.0:
            out_w = float(rl.get_screen_width())
        if out_h <= 0.0:
            out_h = float(rl.get_screen_height())
        if screen_w is None:
            # Prefer live output dimensions by default. Cached config-sized
            # values can lag during gameplay/menu handoffs.
            if out_w > 0.0:
                screen_w = out_w
            else:
                screen_w = float(self.screen_width or out_w)
        if screen_h is None:
            if out_h > 0.0:
                screen_h = out_h
            else:
                screen_h = float(self.screen_height or out_h)
        if screen_w <= 0.0:
            screen_w = out_w if out_w > 0.0 else float(self.screen_width or 1.0)
        if screen_h <= 0.0:
            screen_h = out_h if out_h > 0.0 else float(self.screen_height or 1.0)
        screen_w, screen_h = self._fit_view_window(screen_w, screen_h)
        cam = self._clamp_camera(camera, screen_w, screen_h)

        if self.render_target is None or not self._render_target_ready:
            rl.draw_rectangle(0, 0, int(out_w + 0.5), int(out_h + 0.5), TERRAIN_CLEAR_COLOR)
            return

        target = self.render_target
        u0 = -cam.x / float(self.width)
        v0 = -cam.y / float(self.height)
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
        if self.terrain_filter == 2.0:
            rl.set_texture_filter(target.texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
        # Disable alpha blending when drawing terrain to screen - the render target's
        # alpha channel may be < 1.0 after stamp blending, but terrain should be opaque.
        with _blend_custom(rd.RL_ONE, rd.RL_ZERO, rd.RL_FUNC_ADD):
            rl.draw_texture_pro(target.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        if self.terrain_filter == 2.0:
            rl.set_texture_filter(target.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)

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
            angle = ((rng.rand() % TERRAIN_ROTATION_MAX) * 0.01) % math.tau
            # IMPORTANT: The exe consumes RNG as rotation, then Y, then X.
            y = ((rng.rand() % span_h) - TERRAIN_PATCH_OVERSCAN) * inv_scale
            x = ((rng.rand() % span_w) - TERRAIN_PATCH_OVERSCAN) * inv_scale
            # raylib's DrawTexturePro positions the quad by the *origin point*,
            # while the original engine uses x/y as the quad top-left.
            dst = rl.Rectangle(float(x + size * 0.5), float(y + size * 0.5), size, size)
            rl.draw_texture_pro(texture, src, dst, origin, math.degrees(angle), tint)

    def _clamp_camera(self, camera: Vec2, screen_w: float, screen_h: float) -> Vec2:
        cam_x = camera.x
        cam_y = camera.y
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_y > -1.0:
            cam_y = -1.0
        min_x = screen_w - float(self.width)
        min_y = screen_h - float(self.height)
        if cam_x < min_x:
            cam_x = min_x
        if cam_y < min_y:
            cam_y = min_y
        return Vec2(cam_x, cam_y)

    def _ensure_render_target(self, render_w: int, render_h: int) -> bool:
        if self.render_target is not None:
            if self.render_target.texture.width == render_w and self.render_target.texture.height == render_h:
                return True
            rl.unload_render_texture(self.render_target)
            self.render_target = None
            self._render_target_ready = False

        try:
            candidate = rl.load_render_texture(render_w, render_h)
        except (RuntimeError, OSError, ValueError):
            return False

        if candidate.id == 0 or not rl.is_render_texture_valid(candidate):
            if candidate.id:
                rl.unload_render_texture(candidate)
            return False
        if (
            candidate.texture.width <= 0
            or candidate.texture.height <= 0
        ):
            rl.unload_render_texture(candidate)
            return False

        self.render_target = candidate
        self._render_target_ready = False
        self._render_target_warmup_passes = 1
        rl.set_texture_filter(self.render_target.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        rl.set_texture_wrap(self.render_target.texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
        return True

    def _render_target_size_for(self, scale: float) -> tuple[int, int]:
        pixel_scale = 1.0
        screen_w = int(rl.get_screen_width())
        screen_h = int(rl.get_screen_height())
        render_w = int(rl.get_render_width())
        render_h = int(rl.get_render_height())
        if render_w == screen_w * 2 and render_h == screen_h * 2:
            pixel_scale = 2.0
        render_w = max(1, int((self.width * pixel_scale) / scale))
        render_h = max(1, int((self.height * pixel_scale) / scale))
        return render_w, render_h

    def _normalized_texture_scale(self) -> float:
        scale = self.texture_scale
        if scale < 0.5:
            scale = 0.5
        screen_w = int(rl.get_screen_width())
        screen_h = int(rl.get_screen_height())
        render_w = int(rl.get_render_width())
        render_h = int(rl.get_render_height())
        if render_w == screen_w * 2 and render_h == screen_h * 2:
            scale *= 0.5
        return scale

    def _set_stamp_filters(self, *, point: bool) -> None:
        self._set_texture_filters(
            (self.texture, self.overlay, self.overlay_detail),
            point=point,
        )

    @staticmethod
    def _set_texture_filters(textures: Iterable[rl.Texture | None], *, point: bool) -> None:
        mode = rl.TextureFilter.TEXTURE_FILTER_POINT if point else rl.TextureFilter.TEXTURE_FILTER_BILINEAR
        for texture in textures:
            if texture is None:
                continue
            if texture.id <= 0:
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
            rd.RL_ZERO,
            rd.RL_ONE_MINUS_SRC_ALPHA,
            rd.RL_ZERO,
            rd.RL_ONE,
            rd.RL_FUNC_ADD,
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
        with _blend_custom_separate(
            rd.RL_SRC_ALPHA,
            rd.RL_ONE_MINUS_SRC_ALPHA,
            rd.RL_ZERO,
            rd.RL_ONE,
            rd.RL_FUNC_ADD,
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
