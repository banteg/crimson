"""Lazy companion ground materials, replayed from the same ordered terrain bakes as albedo."""

from __future__ import annotations

import math
from collections.abc import Generator, Iterator, Sequence
from contextlib import contextmanager
from itertools import groupby
from typing import TYPE_CHECKING, NamedTuple

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.blend import blend_custom, opaque_blend
from grim.edr import (
    load_float_render_texture,
    load_optional_float_render_texture,
    reclaim_optional_targets,
    register_optional_reclaimer,
    unregister_optional_reclaimer,
)
from grim.geom import Vec2
from grim.raylib_api import rd, rl, rl_color, rl_rectangle, rl_vector2
from grim.terrain_render import GroundRenderer
from grim.terrain_stamps import TerrainLayers
from grim.texture_mode import restore_current_target, texture_mode

from ...creatures.anim import creature_corpse_frame_for_type
from ...effects_atlas import EffectId
from ...sim.terrain_fx import TerrainFxBatch
from ..terrain_fx import FxQueueTextures, bake_terrain_fx_batch
from ..world.atlas import effect_cell_src
from .continuous_beam import FIRE_DIRECT_GAIN, ION_DIRECT_GAIN, prepare_beam_lights
from .ground_tiles import GroundLightTiles, build_ground_tiles
from .hdr import _HDR_TONEMAP_VS_330
from .heat_vision import HeatVision
from .material_history import MaterialHistory
from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight, collect_material_lights
from .material_shaders import (
    BEAM_VISIBILITY_FRAGMENT,
    GROUND_FRAGMENT,
    GROUND_NORMALS_FRAGMENT,
    STAMP_FRAGMENT,
)
from .reflection_occlusion import (
    BodyVolume,
    ReflectionOcclusion,
    bonus_body_volumes,
    build_occlusion_grid,
    creature_body_volumes,
    player_body_volumes,
)

if TYPE_CHECKING:
    from ..frame import RenderFrame


# Every four selected sources share one RGBA group in a 4x2 coarse world-anchored
# visibility atlas (ground_visibility.glsl), snapped to VISIBILITY_TEXEL world units.
# The atlas binds past raylib's batch texture units, which hold the ground's maps.
VISIBILITY_TEXEL = 4.0
BEAM_VISIBILITY_ROWS = MAX_MATERIAL_LIGHTS // 16
BEAM_VISIBILITY_UNIT = 5
LIGHT_TILES_UNIT = 6
NORMAL_TEX_UNIT = 7
_NORMAL_DIRTY_GRID = 32
# Debug views where ground.frag returns before reading u_light_tiles.
_UNLIT_DEBUG_VIEWS = frozenset((1, 2, 3, 4, 9, 10, 11, 12))

_FLOAT_UNIFORM_KINDS = {
    1: rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
    2: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
    4: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
}


def _uniform(shader: rl.Shader, name: str, values: list[float]) -> None:
    values_buffer = rl.ffi.new(f"float[{len(values)}]", values)
    rl.set_shader_value(
        shader,
        rl.get_shader_location(shader, name),
        rl.ffi.cast("void *", values_buffer),
        _FLOAT_UNIFORM_KINDS[len(values)],
    )


def _integer(shader: rl.Shader, name: str, value: int) -> None:
    rl.set_shader_value(
        shader,
        rl.get_shader_location(shader, name),
        rl.ffi.new("int *", value),
        rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
    )


def _location(shader: rl.Shader, locations: dict[str, int], name: str) -> int:
    if name not in locations:
        locations[name] = int(rl.get_shader_location(shader, name))
    return locations[name]


def _apply_uniforms(shader: rl.Shader, locations: dict[str, int], uniforms: list[tuple[str, list[float], int]]) -> None:
    """(name, values, components) uniforms; 0 components is one int."""
    for name, values, components in uniforms:
        location = _location(shader, locations, name)
        if components == 0:
            rl.set_shader_value(shader, location, rl.ffi.new("int *", int(values[0])),
                                rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
            continue
        buffer = rl.ffi.new("float[]", values)
        rl.set_shader_value_v(shader, location, rl.ffi.cast("void *", buffer), _FLOAT_UNIFORM_KINDS[components],
                              len(values) // components)


def _bind_unit(
    shader: rl.Shader | None, location: int, texture: rl.Texture | None, *, unit: int = BEAM_VISIBILITY_UNIT,
) -> None:
    """Binds `texture` to `unit` for `shader`'s sampler at `location`, or unbinds it."""
    rl.rl_active_texture_slot(unit)
    if texture is None:
        rl.rl_disable_texture()
    else:
        rl.rl_enable_texture(texture.id)
        if shader is not None and location >= 0:
            rl.set_shader_value(shader, location, rl.ffi.new("int *", unit),
                                rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
    rl.rl_active_texture_slot(0)


def _shader(fragment: str) -> rl.Shader:
    shader = rl.load_shader_from_memory(_HDR_TONEMAP_VS_330, fragment)
    if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
        raise RuntimeError("ground material shader compilation failed")
    return shader


@contextmanager
def _coverage_blend(*, ice: bool) -> Generator[None]:
    # RGB stores alpha-over material weights. A stores ice coverage, not blend opacity:
    # ice contributes a, other materials contribute zero, and all occlude previous ice by (1-a).
    factors = (
        rd.RL_SRC_ALPHA, rd.RL_ONE_MINUS_SRC_ALPHA,
        rd.RL_ONE if ice else rd.RL_ZERO, rd.RL_ONE_MINUS_SRC_ALPHA,
        rd.RL_FUNC_ADD, rd.RL_FUNC_ADD,
    )
    rl.rl_set_blend_factors_separate(*factors)
    rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM_SEPARATE)
    rl.rl_set_blend_factors_separate(*factors)
    try:
        yield
    finally:
        rl.end_blend_mode()


class _MaterialStamp(NamedTuple):
    texture: rl.Texture
    src: rl.Rectangle
    dst: rl.Rectangle
    origin: rl.Vector2
    rotation: float
    tint: rl.Color
    kind: int
    elapsed_s: float


class MaterialGroundRenderer(GroundRenderer):
    # CPU-only history permits a late classic -> RTX toggle without changing classic's GPU work.
    # Batches are immutable render output, never simulation state or RNG consumers.
    material_batches: MaterialHistory = msgspec.field(default_factory=MaterialHistory)
    material_layers: TerrainLayers | None = None
    surface: rl.RenderTexture | None = None
    coverage: rl.RenderTexture | None = None
    normals: rl.RenderTexture | None = None
    normals_failed_size: tuple[int, int] | None = None
    normals_dirty: bool = True
    normals_full: bool = True
    normals_dirty_tiles: list[int] = msgspec.field(default_factory=lambda: [0] * _NORMAL_DIRTY_GRID)
    substrate: GroundRenderer | None = None
    stamp_shader: rl.Shader | None = None
    material_shader: rl.Shader | None = None
    fallback_material_shader: rl.Shader | None = None
    normals_shader: rl.Shader | None = None
    normals_locations: dict[str, int] = msgspec.field(default_factory=dict)
    wetness_epoch: float = 0.0
    stamp_locations: dict[str, int] = msgspec.field(default_factory=dict)

    material_locations: dict[str, int] = msgspec.field(default_factory=dict)
    fallback_material_locations: dict[str, int] = msgspec.field(default_factory=dict)
    beam_shader: rl.Shader | None = None
    beam_locations: dict[str, int] = msgspec.field(default_factory=dict)
    beam_atlas: rl.RenderTexture | None = None
    light_tiles: GroundLightTiles = msgspec.field(default_factory=GroundLightTiles)
    reflection_occlusion: ReflectionOcclusion = msgspec.field(default_factory=ReflectionOcclusion)
    heat_vision: HeatVision = msgspec.field(default_factory=HeatVision)

    def reset_materials(self) -> None:
        self.reflection_occlusion.close()
        self.heat_vision.clear()
        if self.substrate is not None:
            self.substrate.close()
            self.substrate = None
        for target in (self.surface, self.coverage):
            if target is not None:
                rl.unload_render_texture(target)
        self.surface = self.coverage = None
        # Retain any existing normals target across replay seeks; invalidate contents for full rebake.
        self.normals_dirty = True
        self.normals_full = True
        self.normals_dirty_tiles = [0] * _NORMAL_DIRTY_GRID
        self.normals_failed_size = None
        self.wetness_epoch = 0.0
        self.material_batches.clear()

    def close(self) -> None:
        self.reset_materials()
        unregister_optional_reclaimer(self.evict_relief_cache)
        if self.normals is not None:
            rl.unload_render_texture(self.normals)
            self.normals = None
        self.normals_failed_size = None
        self.heat_vision.close()
        for shader in (
            self.stamp_shader,
            self.material_shader,
            self.fallback_material_shader,
            self.normals_shader,
            self.beam_shader,
        ):
            if shader is not None:
                rl.unload_shader(shader)
        self.stamp_shader = self.material_shader = self.fallback_material_shader = self.normals_shader = (
            self.beam_shader
        ) = None
        self.material_locations.clear()
        self.fallback_material_locations.clear()
        self.normals_locations.clear()
        self.beam_locations.clear()
        if self.beam_atlas is not None:
            rl.unload_render_texture(self.beam_atlas)
            self.beam_atlas = None
        self.light_tiles.close()
        self.material_layers = None
        super().close()

    def _generate_texture(self, layers: TerrainLayers, texture_scale: float) -> None:
        if self.normals is not None:
            scale = min(max(texture_scale, 0.5), 4.0)
            target_w, target_h = self._render_target_size_for(scale)
            if int(self.normals.texture.width) != target_w or int(self.normals.texture.height) != target_h:
                unregister_optional_reclaimer(self.evict_relief_cache)
                rl.unload_render_texture(self.normals)
                self.normals = None
        self.reset_materials()
        self.material_layers = layers
        super()._generate_texture(layers, texture_scale)

    def evict_relief_cache(self) -> bool:
        """Release optional cached relief storage so required RTX targets can retry allocation."""
        unregister_optional_reclaimer(self.evict_relief_cache)
        if self.normals is None:
            return False
        rl.unload_render_texture(self.normals)
        self.normals = None
        if self.render_target is not None:
            self.normals_failed_size = (
                int(self.render_target.texture.width),
                int(self.render_target.texture.height),
            )
        return True

    def _initialize_materials(self) -> None:
        try:
            self._allocate_materials()
        except RuntimeError:
            freed = self.evict_relief_cache()
            freed |= reclaim_optional_targets()
            if not freed:
                raise
            # Evict all optional relief caches (including menu terrain) and retry required targets once.
            self._allocate_materials()

    def _allocate_materials(self) -> None:
        assert self.render_target is not None
        if self.stamp_shader is None:
            self.stamp_shader = _shader(STAMP_FRAGMENT)
            self.stamp_locations = {
                name: int(rl.get_shader_location(self.stamp_shader, name)) for name in ("u_kind", "u_pass", "u_wetness")
            }
        if self.material_shader is None:
            self.material_shader = _shader(GROUND_FRAGMENT)
        size = self.render_target.texture
        # Full precision preserves small weighted wetness contributions across epoch rebases.
        surface = load_float_render_texture(
            size.width,
            size.height,
            pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32,
        )
        coverage: rl.RenderTexture | None = None
        pristine = GroundRenderer(self.texture, self.overlay, self.overlay_detail, width=self.width, height=self.height)
        try:
            coverage = rl.load_render_texture(size.width, size.height)
            if coverage.id <= 0 or not rl.rl_framebuffer_complete(coverage.id):
                raise RuntimeError("ground material coverage framebuffer is incomplete")
            rl.set_texture_filter(coverage.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
            rl.set_texture_wrap(coverage.texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
            with texture_mode(coverage):
                rl.clear_background(rl.BLANK)
            pristine.render_pristine(
                self.material_layers or TerrainLayers(base=(), overlay=(), detail=()),
                target_size=(size.width, size.height),
            )
            with texture_mode(surface), opaque_blend():
                rl.clear_background(rl_color(10, 0, 0, 115))
                if pristine.render_target is not None:
                    _integer(self.stamp_shader, "u_kind", 0)
                    _integer(self.stamp_shader, "u_pass", 0)
                    rl.begin_shader_mode(self.stamp_shader)
                    try:
                        rl.draw_texture_pro(
                            pristine.render_target.texture,
                            rl_rectangle(0, 0, size.width, -size.height),
                            rl_rectangle(0, 0, size.width, size.height),
                            rl_vector2(0, 0),
                            0,
                            rl.WHITE,
                        )
                    finally:
                        rl.end_shader_mode()
            self.surface, self.coverage = surface, coverage
            self.normals_dirty = True
            self.normals_full = True
            self.normals_dirty_tiles = [0] * _NORMAL_DIRTY_GRID
            self.substrate = pristine
        except BaseException:
            rl.unload_render_texture(surface)
            if coverage is not None:
                rl.unload_render_texture(coverage)
            raise
        finally:
            if self.substrate is not pristine:
                pristine.close()

    def _stamp_commands(self, commands: list[_MaterialStamp]) -> None:
        """Each channel sees the original order, with only three target bindings per chunk."""
        assert self.stamp_shader is not None and self.surface is not None and self.coverage is not None
        sh = self.stamp_shader
        int_buffer = rl.ffi.new("int *")
        float_buffer = rl.ffi.new("float *")

        def integer(name: str, value: int) -> None:
            int_buffer[0] = value
            rl.set_shader_value(sh, self.stamp_locations[name], int_buffer, rl.ShaderUniformDataType.SHADER_UNIFORM_INT)

        for pass_id, target in enumerate((self.coverage, self.surface, self.surface)):
            selected = (command for command in commands if pass_id != 2 or command.kind != 1)
            # Wetness is constant for all blood in a tick; other passes need only material kind.
            groups = groupby(
                selected,
                key=lambda command: (
                    command.kind,
                    command.elapsed_s if pass_id == 1 and command.kind == 1 else 0.0,
                ),
            )
            with texture_mode(target):
                integer("u_pass", pass_id)
                rl.begin_shader_mode(sh)
                try:
                    for (kind, elapsed_s), group in groups:
                        rl.rl_draw_render_batch_active()
                        integer("u_kind", kind)
                        if pass_id == 1 and kind == 1:
                            float_buffer[0] = math.exp((elapsed_s - self.wetness_epoch) / 45.0)
                            rl.set_shader_value(
                                sh,
                                self.stamp_locations["u_wetness"],
                                float_buffer,
                                rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
                            )
                        if pass_id == 0:
                            mask = (True, True, True, True)
                            blend = _coverage_blend(ice=kind == 5)
                        elif pass_id == 1:
                            mask = (kind != 1, True, True, False)
                            blend = blend_custom(
                                rd.RL_ONE if kind == 1 else rd.RL_SRC_ALPHA, rd.RL_ONE_MINUS_SRC_ALPHA, rd.RL_FUNC_ADD,
                            )
                        else:
                            mask = (False, False, False, True)
                            blend = blend_custom(rd.RL_ONE, rd.RL_ONE_MINUS_SRC_ALPHA, rd.RL_FUNC_ADD)
                        rl.rl_color_mask(*mask)
                        with blend:
                            for command in group:
                                rl.draw_texture_pro(
                                    command.texture,
                                    command.src,
                                    command.dst,
                                    command.origin,
                                    command.rotation,
                                    command.tint,
                                )
                finally:
                    rl.rl_draw_render_batch_active()
                    rl.rl_color_mask(True, True, True, True)
                    rl.end_shader_mode()
        if commands:
            self._mark_normals_commands(commands)

    def _mark_normals_commands(self, commands: list[_MaterialStamp]) -> None:
        assert self.surface is not None
        if self.normals_dirty and self.normals_full:
            return
        tex_w = max(1.0, float(self.surface.texture.width))
        tex_h = max(1.0, float(self.surface.texture.height))
        grid = _NORMAL_DIRTY_GRID
        pad = 2.0
        marked = False
        for cmd in commands:
            rad = math.radians(cmd.rotation)
            c = math.cos(rad)
            s = math.sin(rad)
            ox = float(cmd.origin.x)
            oy = float(cmd.origin.y)
            w = float(cmd.dst.width)
            h = float(cmd.dst.height)
            cx = float(cmd.dst.x)
            cy = float(cmd.dst.y)
            xs = [cx + lx * c - ly * s for lx, ly in ((-ox, -oy), (w - ox, -oy), (w - ox, h - oy), (-ox, h - oy))]
            ys = [cy + lx * s + ly * c for lx, ly in ((-ox, -oy), (w - ox, -oy), (w - ox, h - oy), (-ox, h - oy))]
            min_x, max_x = min(xs), max(xs)
            min_y, max_y = min(ys), max(ys)
            if max_x <= 0.0 or max_y <= 0.0 or min_x >= tex_w or min_y >= tex_h:
                continue
            tx0 = max(0, min(grid - 1, math.floor((min_x - pad) * grid / tex_w)))
            ty0 = max(0, min(grid - 1, math.floor((min_y - pad) * grid / tex_h)))
            tx1 = max(0, min(grid - 1, math.floor((max_x + pad) * grid / tex_w)))
            ty1 = max(0, min(grid - 1, math.floor((max_y + pad) * grid / tex_h)))
            if tx1 < tx0 or ty1 < ty0:
                continue
            row_mask = ((1 << (tx1 - tx0 + 1)) - 1) << tx0
            for ty in range(ty0, ty1 + 1):
                self.normals_dirty_tiles[ty] |= row_mask
            marked = True
        if marked:
            self.normals_dirty = True
            self.normals_full = False

    def _ensure_normals(self) -> rl.RenderTexture | None:
        assert self.surface is not None and self.coverage is not None
        size = self.surface.texture
        norm_w = int(size.width)
        norm_h = int(size.height)
        if (
            self.normals is None
            or int(self.normals.texture.width) != norm_w
            or int(self.normals.texture.height) != norm_h
        ):
            if self.normals is not None:
                unregister_optional_reclaimer(self.evict_relief_cache)
                rl.unload_render_texture(self.normals)
                self.normals = None
            if self.normals_failed_size == (norm_w, norm_h):
                return None
            try:
                self.normals = load_optional_float_render_texture(
                    norm_w,
                    norm_h,
                    pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R16G16B16A16,
                )
            except RuntimeError:
                restore_current_target()
                self.normals_failed_size = (norm_w, norm_h)
                return None
            register_optional_reclaimer(self.evict_relief_cache)
            self.normals_failed_size = None
            rl.set_texture_filter(self.normals.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
            rl.set_texture_wrap(self.normals.texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
            self.normals_dirty = True
            self.normals_full = True
            self.normals_dirty_tiles = [0] * _NORMAL_DIRTY_GRID
        if not self.normals_dirty:
            return self.normals
        if self.normals_shader is None:
            self.normals_shader = _shader(GROUND_NORMALS_FRAGMENT)
        sh = self.normals_shader
        grid = _NORMAL_DIRTY_GRID
        dirty_count = sum(row.bit_count() for row in self.normals_dirty_tiles)
        full = self.normals_full or dirty_count == 0 or dirty_count * 2 >= grid * grid
        with texture_mode(self.normals), opaque_blend():
            rl.begin_shader_mode(sh)
            try:
                rl.set_shader_value_texture(
                    sh, _location(sh, self.normals_locations, "u_surface_tex"), self.surface.texture,
                )
                rl.set_shader_value_texture(
                    sh, _location(sh, self.normals_locations, "u_material_tex"), self.coverage.texture,
                )
                origin = rl_vector2(0, 0)
                if full:
                    rl.draw_texture_pro(
                        self.surface.texture,
                        rl_rectangle(0, 0, float(norm_w), -float(norm_h)),
                        rl_rectangle(0, 0, float(norm_w), float(norm_h)),
                        origin,
                        0,
                        rl.WHITE,
                    )
                else:
                    for ty, row in enumerate(self.normals_dirty_tiles):
                        if not row:
                            continue
                        py0 = ty * norm_h // grid
                        py1 = ((ty + 1) * norm_h + grid - 1) // grid
                        tx = 0
                        while tx < grid:
                            if not (row & (1 << tx)):
                                tx += 1
                                continue
                            tx0 = tx
                            while tx < grid and (row & (1 << tx)):
                                tx += 1
                            px0 = tx0 * norm_w // grid
                            px1 = (tx * norm_w + grid - 1) // grid
                            w_span = float(px1 - px0)
                            h_span = float(py1 - py0)
                            # Draw each dirty span directly with matching render-texture UVs (negative src height).
                            rl.draw_texture_pro(
                                self.surface.texture,
                                rl_rectangle(float(px0), float(norm_h - py1), w_span, -h_span),
                                rl_rectangle(float(px0), float(py0), w_span, h_span),
                                origin,
                                0,
                                rl.WHITE,
                            )
                rl.rl_draw_render_batch_active()
            finally:
                rl.end_shader_mode()
        self.normals_dirty = False
        self.normals_full = False
        self.normals_dirty_tiles = [0] * grid
        return self.normals

    def _rebase_wetness(self, epoch: float) -> None:
        """Rescale G occasionally, keeping exp(deposit-epoch) bounded even in very long runs."""
        assert self.surface is not None and self.stamp_shader is not None
        sh = self.stamp_shader
        with texture_mode(self.surface), blend_custom(rd.RL_ZERO, rd.RL_SRC_COLOR, rd.RL_FUNC_ADD):
            _integer(sh, "u_pass", 3)
            _uniform(sh, "u_wetness", [math.exp((self.wetness_epoch - epoch) / 45.0)])
            rl.begin_shader_mode(sh)
            try:
                rl.rl_color_mask(False, True, False, False)
                rl.draw_rectangle(0, 0, self.surface.texture.width, self.surface.texture.height, rl.WHITE)
                rl.rl_draw_render_batch_active()
            finally:
                rl.rl_color_mask(True, True, True, True)
                rl.end_shader_mode()
        self.wetness_epoch = epoch

    def bake_materials(self, particles: rl.Texture, bodyset: rl.Texture) -> None:
        if not self.render_target_ready():
            return
        if self.surface is None:
            self._initialize_materials()
        assert self.substrate is not None
        for batches in self.material_batches.chunks():
            if batches[-1].elapsed_s - self.wetness_epoch > 180.0:
                self._rebase_wetness(batches[0].elapsed_s)
            commands: list[_MaterialStamp] = []
            for batch in batches:
                clean = msgspec.structs.replace(
                    batch,
                    decals=tuple(
                        entry
                        for entry in batch.decals
                        if not EffectId.EFFECT_03 <= entry.effect_id <= EffectId.BLOOD_SPLATTER
                    ),
                )
                bake_terrain_fx_batch(
                    self.substrate,
                    batch=clean,
                    textures=FxQueueTextures(particles, bodyset),
                    corpse_frame_for_type=creature_corpse_frame_for_type,
                )
                commands.extend(self._commands(batch, particles, bodyset))
            self._stamp_commands(commands)
        # The persistent GPU targets now own this history; keep only future, unbaked deposits.
        # Relief packing runs lazily in surface_scope() after required shadow/visibility allocations.
        self.material_batches.clear()

    def _commands(self, batch: TerrainFxBatch, particles: rl.Texture, bodyset: rl.Texture) -> Iterator[_MaterialStamp]:
        assert self.render_target is not None
        scale = self.render_target.texture.width / self.width
        for entry in batch.decals:
            src = effect_cell_src(particles, entry.effect_id)
            if src is None:
                continue
            kind = 0
            if EffectId.EFFECT_03 <= entry.effect_id <= EffectId.BLOOD_SPLATTER:
                kind = 1
            elif entry.effect_id == EffectId.CASING:
                kind = 3
            elif entry.effect_id == EffectId.AURA and entry.color.r <= 0.05:
                kind = 4
            elif entry.effect_id in (
                EffectId.FREEZE_SHARD_0,
                EffectId.FREEZE_SHARD_1,
                EffectId.FREEZE_SHARD_2,
                EffectId.FREEZE_SHATTER,
            ):
                kind = 5
            if not kind:
                continue
            w, h = entry.width * scale, entry.height * scale
            yield _MaterialStamp(
                particles,
                src,
                rl_rectangle(entry.pos.x * scale, entry.pos.y * scale, w, h),
                rl_vector2(w * 0.5, h * 0.5),
                math.degrees(entry.rotation),
                entry.color.to_rl(),
                kind,
                batch.elapsed_s,
            )
        for corpse in batch.corpses:
            frame = creature_corpse_frame_for_type(corpse.creature_type_id)
            size = corpse.scale * scale
            offset = 2.0 / scale / self.width
            yield _MaterialStamp(
                bodyset,
                rl_rectangle(
                    (frame & 3) * bodyset.width / 4,
                    ((frame & 15) >> 2) * bodyset.height / 4,
                    bodyset.width / 4,
                    bodyset.height / 4,
                ),
                rl_rectangle(
                    corpse.top_left.x * scale - offset + size * 0.5,
                    corpse.top_left.y * scale - offset + size * 0.5,
                    size,
                    size,
                ),
                rl_vector2(size * 0.5, size * 0.5),
                math.degrees(corpse.rotation - math.pi * 0.5),
                corpse.color.to_rl(),
                2,
                batch.elapsed_s,
            )

    def _material_location(self, name: str) -> int:
        assert self.material_shader is not None
        return _location(self.material_shader, self.material_locations, name)

    @contextmanager
    def material_scope(
        self,
        frame: RenderFrame,
        *,
        view_center: Vec2 = Vec2(512, 512),
        view_size: Vec2 | None = None,
        debug: int | None = None,
        lights: Sequence[MaterialLight] | None = None,
    ) -> Generator[None]:
        """The live world's material program and body visibility."""
        shadows = frame.config is None or frame.config.display.shadows_enabled
        if lights is None:
            lights = collect_material_lights(frame, view_center=view_center, view_size=view_size)
        lights = lights[:MAX_MATERIAL_LIGHTS]
        bodies = (
            [body for creature in frame.creatures.entries for body in creature_body_volumes(creature)]
            + [body for player in frame.players for body in player_body_volumes(player)]
            + [body for bonus in frame.state.bonus_pool.entries for body in bonus_body_volumes(bonus)]
            if shadows and any(light.reflection_gain > 0 or light.illumination_gain > 0 for light in lights) else []
        )
        with self.surface_scope(
            frame.resources, elapsed_ms=frame.elapsed_ms, lights=lights, bodies=bodies, shadows=shadows,
            view_center=view_center, view_size=view_size,
            debug=int(frame.rtx_debug) if debug is None else debug, debug_display=debug is None,
        ):
            yield

    @contextmanager
    def surface_scope(
        self,
        resources: RuntimeResources,
        *,
        elapsed_ms: float,
        lights: Sequence[MaterialLight] = (),
        bodies: Sequence[BodyVolume] = (),
        shadows: bool = False,
        view_center: Vec2 = Vec2(512, 512),
        view_size: Vec2 | None = None,
        debug: int = 0,
        debug_display: bool = True,
    ) -> Generator[None]:
        """Shade retained materials, including menu terrain without a live world."""
        self.reflection_occlusion.grid = None
        if not self.render_target_ready():
            yield
            return
        self.bake_materials(resources.texture(TextureId.PARTICLES), resources.texture(TextureId.BODYSET))
        assert self.material_shader is not None and self.surface is not None and self.coverage is not None
        uniforms: list[tuple[str, list[float], int]] = []

        def put(name: str, values: list[float], components: int = 0) -> None:
            uniforms.append((name, values, components or len(values)))

        def put_int(name: str, value: int) -> None:
            uniforms.append((name, [value], 0))

        put("u_ground_size", [float(self.width), float(self.height)])
        put("u_time_s", [elapsed_ms * 0.001 - self.wetness_epoch])
        put_int("u_debug", debug)
        put_int("u_debug_display", int(debug_display))
        put_int("u_spec_light_count", len(lights))
        has_beam_lights = any(
            light.beam_profile is not None and light.illumination_gain > 0 for light in lights
        )
        put_int("u_has_beam_lights", int(has_beam_lights))
        shapes = [0.0] * (4 * len(lights))
        if has_beam_lights:
            shapes, _ = prepare_beam_lights(lights)
            put("u_beam_gain", [ION_DIRECT_GAIN, FIRE_DIRECT_GAIN])
            put("u_beam_shape[0]", shapes, 4)
        # Keep halo support in the shared body grid for reflection-only beams too so corner rays straddling
        # a beam's reflection cutoff keep their blockers when illumination drops (rtx_lights.cpp's rtx_build_occlusion),
        # without expanding the ground visibility pass (`shapes` stays gated on illumination).
        _, grid_lights = prepare_beam_lights(lights, require_illumination=False)
        grid = build_occlusion_grid(
            bodies, grid_lights, width=self.width, height=self.height, illumination=shadows,
        )
        occlusion_texture = self.reflection_occlusion.upload(grid) if grid.occludes else None
        put("u_occlusion_grid", [
            grid.origin.x, grid.origin.y, float(grid.columns if grid.occludes else 0), float(grid.rows),
        ])
        put("u_occlusion_cell_size", [grid.cell_size])
        put("u_spec_pos[0]", [v for light in lights for v in (light.pos.x, light.pos.y, light.radius, light.height)], 4)
        put("u_spec_color[0]", [v for light in lights for v in (*light.rgb, light.ring_radius)], 4)
        tails = [light.reflection_tail for light in lights]
        put("u_spec_tail[0]", tails + [0.0] * (-len(tails) % 4), 4)
        put("u_spec_dir[0]", [v for light in lights for v in
                              (light.direction.x, light.direction.y, float(light.broad_illumination), light.length)], 4)
        put("u_spec_response[0]", [v for light in lights for v in light.response], 4)
        if view_size is None:
            view_min = Vec2(0.0, 0.0)
            view_max = Vec2(float(self.width), float(self.height))
        else:
            view_min = view_center - view_size * 0.5
            view_max = view_min + view_size
        atlas = None
        if occlusion_texture is not None and lights and view_max.x > view_min.x and view_max.y > view_min.y:
            origin = Vec2(
                math.floor(view_min.x / VISIBILITY_TEXEL) * VISIBILITY_TEXEL - VISIBILITY_TEXEL,
                math.floor(view_min.y / VISIBILITY_TEXEL) * VISIBILITY_TEXEL - VISIBILITY_TEXEL,
            )
            group_width = math.ceil((view_max.x - view_min.x) / VISIBILITY_TEXEL) + 3
            group_height = math.ceil((view_max.y - view_min.y) / VISIBILITY_TEXEL) + 3
            extent = Vec2(group_width * VISIBILITY_TEXEL, group_height * VISIBILITY_TEXEL)
            put("u_visibility_world", [origin.x, origin.y, extent.x, extent.y])
            put("u_visibility_size", [float(group_width), float(group_height)])
            atlas = self._beam_visibility(
                uniforms,
                occlusion_texture,
                lights,
                shapes,
                origin=origin,
                extent=extent,
                width=group_width,
                height=group_height,
            )
        else:
            put("u_visibility_world", [0.0, 0.0, 0.0, 0.0])
            put("u_visibility_size", [0.0, 0.0])
        if lights and debug not in _UNLIT_DEBUG_VIEWS:
            tile_w, tile_h, tile_masks = build_ground_tiles(
                float(self.width), float(self.height), lights, shapes, beams=has_beam_lights,
            )
        else:
            tile_w, tile_h, tile_masks = 0, 0, b""
        tile_texture = self.light_tiles.upload(tile_w, tile_h, tile_masks) if tile_w > 0 and tile_h > 0 else None
        # Select ground shader after _beam_visibility so atlas allocation can evict optional relief first.
        normals = self._ensure_normals()
        if normals is not None:
            sh = self.material_shader
            locations = self.material_locations
        else:
            if self.fallback_material_shader is None:
                direct_src = GROUND_FRAGMENT.replace("#version 330\n", "#version 330\n#define GROUND_DIRECT_RELIEF 1\n", 1)
                self.fallback_material_shader = _shader(direct_src)
            sh = self.fallback_material_shader
            locations = self.fallback_material_locations
        _apply_uniforms(sh, locations, uniforms)
        tile_size_buf = rl.ffi.new("int[2]", [tile_w, tile_h])
        rl.set_shader_value(
            sh,
            _location(sh, locations, "u_light_tile_size"),
            rl.ffi.cast("void *", tile_size_buf),
            rl.ShaderUniformDataType.SHADER_UNIFORM_IVEC2,
        )
        # GroundRenderer uses opaque blending. Bind auxiliary samplers after that switch,
        # since rlgl flushes (and clears sampler bindings) when changing blend modes.
        with opaque_blend():
            rl.begin_shader_mode(sh)
            try:
                rl.set_shader_value_texture(sh, _location(sh, locations, "u_surface_tex"), self.surface.texture)
                rl.set_shader_value_texture(sh, _location(sh, locations, "u_material_tex"), self.coverage.texture)
                assert self.substrate is not None and self.substrate.render_target is not None
                rl.set_shader_value_texture(
                    sh,
                    _location(sh, locations, "u_substrate_tex"),
                    self.substrate.render_target.texture,
                )
                if atlas is not None:
                    _bind_unit(sh, _location(sh, locations, "u_visibility_tex"), atlas.texture)
                if tile_texture is not None:
                    _bind_unit(
                        sh, _location(sh, locations, "u_light_tiles"), tile_texture, unit=LIGHT_TILES_UNIT,
                    )
                if normals is not None:
                    _bind_unit(sh, _location(sh, locations, "u_normal_tex"), normals.texture, unit=NORMAL_TEX_UNIT)
                yield
            finally:
                rl.end_shader_mode()
                if normals is not None:
                    _bind_unit(None, -1, None, unit=NORMAL_TEX_UNIT)
                if tile_texture is not None:
                    _bind_unit(None, -1, None, unit=LIGHT_TILES_UNIT)
                if atlas is not None:
                    _bind_unit(None, -1, None)

    def _beam_visibility(
        self,
        uniforms: list[tuple[str, list[float], int]],
        occlusion: rl.Texture,
        lights: Sequence[MaterialLight],
        shapes: Sequence[float],
        *,
        origin: Vec2,
        extent: Vec2,
        width: int,
        height: int,
    ) -> rl.RenderTexture:
        """Render the 4x2 coarse world-anchored visibility atlas for `count` canonical sources."""
        if self.beam_shader is None:
            self.beam_shader = _shader(BEAM_VISIBILITY_FRAGMENT)
        atlas = self.beam_atlas
        rows = BEAM_VISIBILITY_ROWS
        if atlas is None or int(atlas.texture.width) != 4 * width or int(atlas.texture.height) != rows * height:
            if atlas is not None:
                rl.unload_render_texture(atlas)
                self.beam_atlas = None
            try:
                atlas = self.beam_atlas = load_float_render_texture(4 * width, rows * height)
            except RuntimeError:
                if not self.evict_relief_cache():
                    restore_current_target()
                    raise
                atlas = self.beam_atlas = load_float_render_texture(4 * width, rows * height)
            rl.set_texture_filter(atlas.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        shader = self.beam_shader
        _apply_uniforms(shader, self.beam_locations, uniforms)
        camera = Vec2(-origin.x, -origin.y)
        # The virtual view fills the atlas's projection; each group's viewport squeezes it into its tile.
        with texture_mode(atlas, scale_x=4 * width / extent.x, scale_y=rows * height / extent.y):
            rl.rl_disable_scissor_test()
            rl.clear_background(rl.WHITE)
            rl.rl_enable_scissor_test()
            for group in range((min(len(lights), MAX_MATERIAL_LIGHTS) + 3) // 4):
                # The same conservative support bounds as client/ground_visibility.h.
                support = []
                for i in range(group * 4, min(len(lights), group * 4 + 4)):
                    light = lights[i]
                    has_diff = light.illumination_gain > 0.0
                    has_spec = light.reflection_gain > 0.0 and light.reflection_reach > 0.0
                    if not has_diff and not has_spec:
                        continue
                    diff_rad = max(1.0, light.radius) if has_diff else 0.0
                    spec_rad = max(0.01, light.reflection_reach) if has_spec else 0.0
                    square = light.direction.x ** 2 + light.direction.y ** 2
                    if light.ring_radius > 0:
                        ex = ey = max(diff_rad, spec_rad) + light.ring_radius
                    elif 0.00009 <= square <= 0.00011:
                        spec_half = max(0.0, light.length * 0.5)
                        diff_half = max(spec_half, shapes[i * 4 + 3]) if has_diff else 0.0
                        ex = ey = max(
                            diff_rad + diff_half if has_diff else 0.0,
                            spec_rad + spec_half if has_spec else 0.0,
                        )
                    else:
                        has_dir = square > 0.0001
                        axis = light.direction / math.sqrt(square) if has_dir else Vec2(1, 0)
                        spec_half = max(0.0, light.length * 0.5) if has_dir else 0.0
                        diff_half = max(spec_half, shapes[i * 4 + 3]) if has_diff else 0.0
                        ex = max(
                            diff_rad + abs(axis.x) * diff_half if has_diff else 0.0,
                            spec_rad + abs(axis.x) * spec_half if has_spec else 0.0,
                        )
                        ey = max(
                            diff_rad + abs(axis.y) * diff_half if has_diff else 0.0,
                            spec_rad + abs(axis.y) * spec_half if has_spec else 0.0,
                        )
                    support.append((light.pos.x - ex, light.pos.y - ey, light.pos.x + ex, light.pos.y + ey))
                if not support:
                    continue
                x0 = max(0, min(width, math.floor((min(b[0] for b in support) - origin.x) / VISIBILITY_TEXEL) - 1))
                y0 = max(0, min(height, math.floor((min(b[1] for b in support) - origin.y) / VISIBILITY_TEXEL) - 1))
                x1 = max(0, min(width, math.ceil((max(b[2] for b in support) - origin.x) / VISIBILITY_TEXEL) + 1))
                y1 = max(0, min(height, math.ceil((max(b[3] for b in support) - origin.y) / VISIBILITY_TEXEL) + 1))
                if x1 <= x0 or y1 <= y0:
                    continue
                rl.rl_draw_render_batch_active()
                rl.rl_viewport(group % 4 * width, group // 4 * height, width, height)
                # Raylib's world top maps to the GL viewport's top.
                rl.rl_scissor(group % 4 * width + x0, group // 4 * height + height - y1, x1 - x0, y1 - y0)
                with opaque_blend():
                    rl.begin_shader_mode(shader)
                    try:
                        rl.set_shader_value_texture(
                            shader, _location(shader, self.beam_locations, "u_occlusion_tex"), occlusion,
                        )
                        _apply_uniforms(shader, self.beam_locations, [("u_visibility_group", [float(group)], 1)])
                        self.draw_view(camera, screen_w=extent.x, screen_h=extent.y, out_w=extent.x, out_h=extent.y)
                    finally:
                        rl.end_shader_mode()
            rl.rl_draw_render_batch_active()
            rl.rl_disable_scissor_test()
            rl.rl_viewport(0, 0, 4 * width, rows * height)
        return atlas
