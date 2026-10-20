"""Lazy companion ground materials, replayed from the same ordered terrain bakes as albedo."""

from __future__ import annotations

import math
from collections.abc import Iterator
from contextlib import contextmanager
from itertools import groupby
from typing import TYPE_CHECKING, NamedTuple

import msgspec

from grim.blend import blend_custom, opaque_blend
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rd, rl, rl_color, rl_rectangle, rl_vector2
from grim.terrain_render import GroundRenderer
from grim.terrain_stamps import TerrainLayers
from grim.texture_mode import texture_mode

from ...creatures.anim import creature_corpse_frame_for_type
from ...effects_atlas import EffectId
from ...sim.terrain_fx import TerrainFxBatch
from ..terrain_fx import FxQueueTextures, bake_terrain_fx_batch
from ..world.atlas import effect_cell_src
from .hdr import _HDR_TONEMAP_VS_330
from .material_history import MaterialHistory
from .material_lights import collect_material_lights
from .material_shaders import GROUND_FRAGMENT, STAMP_FRAGMENT
from .reflection_occlusion import ReflectionOcclusion, build_occlusion_grid, creature_body_volumes

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


@contextmanager
def _coverage_blend(*, ice: bool) -> Iterator[None]:
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
    substrate: GroundRenderer | None = None
    stamp_shader: rl.Shader | None = None
    material_shader: rl.Shader | None = None
    wetness_epoch: float = 0.0
    stamp_locations: dict[str, int] = msgspec.field(default_factory=dict)

    reflection_occlusion: ReflectionOcclusion = msgspec.field(default_factory=ReflectionOcclusion)

    def reset_materials(self) -> None:
        self.reflection_occlusion.close()
        if self.substrate is not None:
            self.substrate.close()
            self.substrate = None
        for target in (self.surface, self.coverage):
            if target is not None:
                rl.unload_render_texture(target)
        self.surface = self.coverage = None
        self.wetness_epoch = 0.0
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

    @contextmanager
    def material_scope(
        self, frame: RenderFrame, *, view_center: Vec2 = Vec2(512, 512), debug: int | None = None,
    ) -> Iterator[None]:
        from grim.assets import TextureId

        self.reflection_occlusion.grid = None
        if not self.render_target_ready():
            yield
            return
        self.bake_materials(frame.resources.texture(TextureId.PARTICLES), frame.resources.texture(TextureId.BODYSET))
        assert self.material_shader is not None and self.surface is not None and self.coverage is not None
        sh = self.material_shader
        _uniform(sh, "u_ground_size", [float(self.width), float(self.height)])
        _uniform(sh, "u_time_s", [frame.elapsed_ms * 0.001 - self.wetness_epoch])
        _integer(sh, "u_debug", int(frame.rtx_debug) if debug is None else debug)
        _integer(sh, "u_debug_display", int(debug is None))
        shadows = frame.config is None or frame.config.display.shadows_enabled
        _integer(sh, "u_dynamic_shadows", int(shadows))
        lights = collect_material_lights(frame, view_center=view_center)
        _integer(sh, "u_spec_light_count", len(lights))
        bodies = (
            [body for creature in frame.creatures.entries for body in creature_body_volumes(creature)]
            if any(light.reflection_gain > 0 or (shadows and light.illumination_gain > 0) for light in lights) else []
        )
        grid = build_occlusion_grid(bodies, lights, width=self.width, height=self.height, illumination=shadows)
        occlusion_texture = self.reflection_occlusion.upload(grid) if grid.body_count else None
        _uniform(sh, "u_occlusion_grid", [
            grid.origin.x, grid.origin.y, float(grid.columns if grid.body_count else 0), float(grid.rows),
        ])
        _uniform(sh, "u_occlusion_cell_size", [grid.cell_size])
        for i, light in enumerate(lights):
            _uniform(sh, f"u_spec_pos[{i}]", [light.pos.x, light.pos.y, light.radius, light.height])
            _uniform(sh, f"u_spec_color[{i}]", [*light.rgb, float(light.length > 0)])
            _uniform(sh, f"u_spec_tail[{i}]", [light.reflection_tail])
            _uniform(sh, f"u_spec_dir[{i}]", [light.direction.x, light.direction.y, float(light.broad_illumination), light.length])
            _uniform(sh, f"u_spec_response[{i}]", list(light.response))
        # GroundRenderer uses opaque blending. Bind auxiliary samplers after that switch,
        # since rlgl flushes (and clears sampler bindings) when changing blend modes.
        with opaque_blend():
            rl.begin_shader_mode(sh)
            try:
                if occlusion_texture is not None:
                    rl.set_shader_value_texture(sh, rl.get_shader_location(sh, "u_occlusion_tex"), occlusion_texture)
                rl.set_shader_value_texture(sh, rl.get_shader_location(sh, "u_surface_tex"), self.surface.texture)
                rl.set_shader_value_texture(sh, rl.get_shader_location(sh, "u_material_tex"), self.coverage.texture)
                assert self.substrate is not None and self.substrate.render_target is not None
                rl.set_shader_value_texture(
                    sh,
                    rl.get_shader_location(sh, "u_substrate_tex"),
                    self.substrate.render_target.texture,
                )
                yield
            finally:
                rl.end_shader_mode()
