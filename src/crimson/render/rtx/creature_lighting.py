"""Lazy, batched RTX creature lighting; classic sprites keep their native draw path."""

from __future__ import annotations

from collections.abc import Generator, Sequence
from contextlib import contextmanager

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from .creature_shaders import CREATURE_FRAGMENT, CREATURE_VERTEX
from .creature_translucency import load_thickness_texture
from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight
from .reflection_occlusion import ReflectionOcclusion


class CreatureLighting(msgspec.Struct):
    shader: rl.Shader | None = None
    locations: dict[str, int] = msgspec.field(default_factory=dict)
    active: bool = False
    light_count: int = 0
    thickness_textures: dict[int, rl.Texture] = msgspec.field(default_factory=dict)
    occlusion: ReflectionOcclusion | None = None

    def prepare(
        self, lights: Sequence[MaterialLight], *, camera: Vec2, view_scale: Vec2,
        occlusion: ReflectionOcclusion | None = None, shadows: bool = True, ambient: float = 1.0,
    ) -> None:
        """Upload bounded emitters once per creature pass, before any body batches."""
        self.light_count = min(len(lights), MAX_MATERIAL_LIGHTS)
        self.occlusion = occlusion
        self.active = bool(lights) or ambient != 1.0
        if not self.active:
            return
        if self.shader is None:
            shader = rl.load_shader_from_memory(CREATURE_VERTEX, CREATURE_FRAGMENT)
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX creature lighting shader compilation failed")
            self.shader = shader
            self.locations = {
                name: int(rl.get_shader_location(shader, name))
                for name in ("u_camera", "u_view_scale", "u_count", "u_pos", "u_rgb", "u_dir", "u_response", "u_thickness",
                             "u_occlusion_tex", "u_occlusion_grid", "u_occlusion_cell_size", "u_dynamic_shadows", "u_ambient")
            }
        shader = self.shader
        # Flush preceding draws before changing values on a possibly reused shader.
        rl.rl_draw_render_batch_active()
        for name, value in (("u_camera", camera), ("u_view_scale", view_scale)):
            buffer = rl.ffi.new("float[2]", [value.x, value.y])
            rl.set_shader_value(
                shader, self.locations[name], rl.ffi.cast("void *", buffer),
                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
            )
        grid = occlusion.grid if occlusion is not None else None
        grid_values = [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)] if grid is not None and grid.body_count else [0.] * 4
        buffer = rl.ffi.new("float[4]", grid_values)
        rl.set_shader_value(shader, self.locations["u_occlusion_grid"], rl.ffi.cast("void *", buffer),
                            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4)
        for name, value in (("u_occlusion_cell_size", grid.cell_size if grid else 64.), ("u_ambient", ambient)):
            rl.set_shader_value(shader, self.locations[name], rl.ffi.new("float *", value),
                                rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT)
        rl.set_shader_value(shader, self.locations["u_dynamic_shadows"], rl.ffi.new("int *", int(shadows)),
                            rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
        lights = lights[:MAX_MATERIAL_LIGHTS]
        rl.set_shader_value(
            shader, self.locations["u_count"], rl.ffi.new("int *", len(lights)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        if not lights:
            return
        values = {
            "u_pos": [v for light in lights for v in (light.pos.x, light.pos.y, light.radius, light.height)],
            "u_rgb": [v for light in lights for v in (*light.rgb, light.ring_radius)],
            "u_dir": [v for light in lights for v in (light.direction.x, light.direction.y, light.reflection_tail, light.length)],
            "u_response": [v for light in lights for v in light.response],
        }
        for name, value in values.items():
            buffer = rl.ffi.new("float[]", value)
            rl.set_shader_value_v(
                shader, self.locations[name], rl.ffi.cast("void *", buffer),
                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4, len(lights),
            )

    @contextmanager
    def scope(self, *, texture: rl.Texture, restore_shader: rl.Shader | None) -> Generator[None]:
        if not self.active or self.shader is None:
            yield
            return
        # Texture IDs remain stable for the owning render resources' lifetime.
        thickness = self.thickness_textures.get(int(texture.id))
        if thickness is None and self.light_count:
            rl.rl_draw_render_batch_active()
            thickness = load_thickness_texture(texture)
            self.thickness_textures[int(texture.id)] = thickness
        rl.rl_draw_render_batch_active()
        try:
            rl.begin_shader_mode(self.shader)
            if thickness is not None:
                rl.set_shader_value_texture(self.shader, self.locations["u_thickness"], thickness)
            if self.occlusion is not None and self.occlusion.grid is not None and self.occlusion.grid.body_count and self.occlusion.texture is not None:
                rl.set_shader_value_texture(self.shader, self.locations["u_occlusion_tex"], self.occlusion.texture)
            yield
        finally:
            # The enclosing world pass uses alpha testing, including after exceptions.
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def close(self) -> None:
        for texture in self.thickness_textures.values():
            rl.unload_texture(texture)
        self.thickness_textures.clear()
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
        self.locations.clear()
        self.active = False
        self.light_count = 0
        self.occlusion = None
