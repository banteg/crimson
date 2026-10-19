"""Lazy companion ground materials, replayed from the same ordered terrain bakes as albedo."""

from __future__ import annotations

import math
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import msgspec

from grim.blend import blend_custom, opaque_blend
from grim.edr import load_float_render_texture
from grim.raylib_api import rd, rl, rl_color, rl_rectangle, rl_vector2
from grim.terrain_render import (
    TERRAIN_BASE_TINT,
    TERRAIN_CLEAR_COLOR,
    TERRAIN_DETAIL_TINT,
    GroundRenderer,
    _terrain_rt_blend,
)
from grim.terrain_stamps import TerrainLayers
from grim.texture_mode import texture_mode

from ...creatures.anim import creature_corpse_frame_for_type
from ...effects_atlas import EffectId
from ...sim.terrain_fx import TerrainFxBatch
from ..terrain_fx import FxQueueTextures, bake_terrain_fx_batch
from ..world.atlas import effect_cell_src
from .hdr import _HDR_TONEMAP_VS_330
from .material_lights import collect_material_lights
from .material_shaders import GROUND_FRAGMENT, STAMP_FRAGMENT

if TYPE_CHECKING:
    from ..frame import RenderFrame


def _uniform(shader: rl.Shader, name: str, values: list[float]) -> None:
    kinds = {
        1: rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        2: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        4: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
    }
    values_buffer = rl.ffi.new(f"float[{len(values)}]", values)
    rl.set_shader_value(
        shader,
        rl.get_shader_location(shader, name),
        rl.ffi.cast("void *", values_buffer),
        kinds[len(values)],
    )


def _integer(shader: rl.Shader, name: str, value: int) -> None:
    rl.set_shader_value(
        shader,
        rl.get_shader_location(shader, name),
        rl.ffi.new("int *", value),
        rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
    )


def _shader(fragment: str) -> rl.Shader:
    shader = rl.load_shader_from_memory(_HDR_TONEMAP_VS_330, fragment)
    if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
        raise RuntimeError("ground material shader compilation failed")
    return shader


class MaterialGroundRenderer(GroundRenderer):
    # CPU-only history permits a late classic -> RTX toggle without changing classic's GPU work.
    # Batches are immutable render output, never simulation state or RNG consumers.
    material_batches: list[TerrainFxBatch] = msgspec.field(default_factory=list)
    material_layers: TerrainLayers | None = None
    surface: rl.RenderTexture | None = None
    coverage: rl.RenderTexture | None = None
    substrate: GroundRenderer | None = None
    stamp_shader: rl.Shader | None = None
    material_shader: rl.Shader | None = None
    material_baked: int = 0

    def reset_materials(self) -> None:
        if self.substrate is not None:
            self.substrate.close()
            self.substrate = None
        for target in (self.surface, self.coverage):
            if target is not None:
                rl.unload_render_texture(target)
        self.surface = self.coverage = None
        self.material_baked = 0
        self.material_batches.clear()

    def close(self) -> None:
        self.reset_materials()
        for shader in (self.stamp_shader, self.material_shader):
            if shader is not None:
                rl.unload_shader(shader)
        self.stamp_shader = self.material_shader = None
        self.material_layers = None
        super().close()

    def _generate_texture(self, layers: TerrainLayers, texture_scale: float) -> None:
        self.reset_materials()
        self.material_layers = layers
        super()._generate_texture(layers, texture_scale)

    def _initialize_materials(self) -> None:
        assert self.render_target is not None
        if self.stamp_shader is None:
            self.stamp_shader = _shader(STAMP_FRAGMENT)
        if self.material_shader is None:
            self.material_shader = _shader(GROUND_FRAGMENT)
        size = self.render_target.texture
        # Full precision matters for an absolute clock in long Survival runs.
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
            # Recreate only the unpainted terrain, at the already allocated dimensions (including DPI).
            if self.material_layers is not None:
                pristine._load_render_target(size.width, size.height)
                assert pristine.render_target is not None
                with texture_mode(pristine.render_target):
                    rl.clear_background(TERRAIN_CLEAR_COLOR)
                    with (
                        pristine.alpha_test.scope(),
                        _terrain_rt_blend(
                            rd.RL_SRC_ALPHA,
                            rd.RL_ONE_MINUS_SRC_ALPHA,
                            rd.RL_FUNC_ADD,
                        ),
                    ):
                        pristine._draw_stamps(self.texture, TERRAIN_BASE_TINT, self.material_layers.base)
                        pristine._draw_stamps(self.overlay, TERRAIN_BASE_TINT, self.material_layers.overlay)
                        pristine._draw_stamps(self.overlay_detail, TERRAIN_DETAIL_TINT, self.material_layers.detail)
            with texture_mode(surface), opaque_blend():
                rl.clear_background(rl_color(10, 0, 0, 115))
                if pristine.render_target is not None:
                    _integer(self.stamp_shader, "u_kind", 0)
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
            pristine._render_target_ready = True
            self.surface, self.coverage = surface, coverage
            self.substrate = pristine
        except BaseException:
            rl.unload_render_texture(surface)
            if coverage is not None:
                rl.unload_render_texture(coverage)
            raise
        finally:
            if self.substrate is not pristine:
                pristine.close()

    def _stamp(
        self,
        texture: rl.Texture,
        src: rl.Rectangle,
        dst: rl.Rectangle,
        origin: rl.Vector2,
        rotation: float,
        tint: rl.Color,
        kind: int,
        elapsed_s: float,
    ) -> None:
        assert self.stamp_shader is not None and self.surface is not None and self.coverage is not None
        sh = self.stamp_shader
        _integer(sh, "u_kind", kind)
        _uniform(
            sh,
            "u_cell",
            [src.x / texture.width, src.y / texture.height, src.width / texture.width, src.height / texture.height],
        )
        _uniform(sh, "u_time", [elapsed_s])
        # Each pass owns/restores both blending and write masks; flush before changing masks.
        for target, pass_id, mask, src_blend, dst_blend in (
            (self.coverage, 0, (True, True, True, False), rd.RL_SRC_ALPHA, rd.RL_ONE_MINUS_SRC_ALPHA),
            (
                self.surface,
                1,
                (kind != 1, False, True, False),
                rd.RL_ONE if kind == 1 else rd.RL_SRC_ALPHA,
                rd.RL_ONE_MINUS_SRC_COLOR if kind == 1 else rd.RL_ONE_MINUS_SRC_ALPHA,
            ),
            (
                self.surface,
                2,
                (False, kind == 1, False, kind != 1),
                rd.RL_ONE,
                rd.RL_ZERO if kind == 1 else rd.RL_ONE_MINUS_SRC_ALPHA,
            ),
        ):
            with texture_mode(target):
                _integer(sh, "u_pass", pass_id)
                rl.begin_shader_mode(sh)
                try:
                    rl.rl_draw_render_batch_active()
                    rl.rl_color_mask(*mask)
                    with blend_custom(src_blend, dst_blend, rd.RL_FUNC_ADD):
                        rl.draw_texture_pro(texture, src, dst, origin, rotation, tint)
                finally:
                    rl.rl_draw_render_batch_active()
                    rl.rl_color_mask(True, True, True, True)
                    rl.end_shader_mode()

    def bake_materials(self, particles: rl.Texture, bodyset: rl.Texture) -> None:
        if not self.render_target_ready():
            return
        if self.surface is None:
            self._initialize_materials()
        assert self.render_target is not None
        scale = self.render_target.texture.width / self.width
        for batch in self.material_batches[self.material_baked :]:
            assert self.substrate is not None
            # Keep clean substrate color under the film. Corpse/scorch/casing painting remains ordered.
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
                self._stamp(
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
                self._stamp(
                    bodyset,
                    self._corpse_src(bodyset, frame),
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
            self.material_baked += 1

    @contextmanager
    def material_scope(self, frame: RenderFrame) -> Iterator[None]:
        from grim.assets import TextureId

        if not self.render_target_ready():
            yield
            return
        self.bake_materials(frame.resources.texture(TextureId.PARTICLES), frame.resources.texture(TextureId.BODYSET))
        assert self.material_shader is not None and self.surface is not None and self.coverage is not None
        sh = self.material_shader
        _uniform(sh, "u_ground_size", [float(self.width), float(self.height)])
        _uniform(sh, "u_time_s", [frame.elapsed_ms * 0.001])
        lights = collect_material_lights(frame)
        _integer(sh, "u_spec_light_count", len(lights))
        for i, light in enumerate(lights):
            _uniform(sh, f"u_spec_pos[{i}]", [light.pos.x, light.pos.y, light.radius, light.height])
            _uniform(sh, f"u_spec_color[{i}]", [*light.rgb, float(light.length > 0)])
            _uniform(sh, f"u_spec_dir[{i}]", [light.direction.x, light.direction.y, 0.0, light.length])
        # GroundRenderer uses opaque blending. Bind auxiliary samplers after that switch,
        # since rlgl flushes (and clears sampler bindings) when changing blend modes.
        with opaque_blend():
            rl.begin_shader_mode(sh)
            try:
                rl.set_shader_value_texture(sh, rl.get_shader_location(sh, "u_surface_tex"), self.surface.texture)
                rl.set_shader_value_texture(sh, rl.get_shader_location(sh, "u_material_tex"), self.coverage.texture)
                assert self.substrate is not None and self.substrate.render_target is not None
                rl.set_shader_value_texture(
                    sh, rl.get_shader_location(sh, "u_substrate_tex"), self.substrate.render_target.texture,
                )
                yield
            finally:
                rl.end_shader_mode()
