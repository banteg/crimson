"""Lazy, batched RTX creature lighting; classic sprites keep their native draw path."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from .creature_shaders import CREATURE_FRAGMENT, CREATURE_VERTEX
from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight


class CreatureLighting(msgspec.Struct):
    shader: rl.Shader | None = None
    locations: dict[str, int] = msgspec.field(default_factory=dict)
    active: bool = False

    def prepare(self, lights: Sequence[MaterialLight], *, camera: Vec2, view_scale: Vec2) -> None:
        """Upload bounded emitters once per creature pass, before any body batches."""
        self.active = bool(lights)
        if not self.active:
            return
        if self.shader is None:
            shader = rl.load_shader_from_memory(CREATURE_VERTEX, CREATURE_FRAGMENT)
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX creature lighting shader compilation failed")
            self.shader = shader
            self.locations = {
                name: int(rl.get_shader_location(shader, name))
                for name in ("u_camera", "u_view_scale", "u_count", "u_pos", "u_rgb", "u_dir", "u_response")
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
        lights = lights[:MAX_MATERIAL_LIGHTS]
        rl.set_shader_value(
            shader, self.locations["u_count"], rl.ffi.new("int *", len(lights)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        values = {
            "u_pos": [v for light in lights for v in (light.pos.x, light.pos.y, light.radius, light.height)],
            "u_rgb": [v for light in lights for v in (*light.rgb, 0.0)],
            "u_dir": [v for light in lights for v in (light.direction.x, light.direction.y, 0.0, light.length)],
            "u_response": [v for light in lights for v in light.response],
        }
        for name, value in values.items():
            buffer = rl.ffi.new("float[]", value)
            rl.set_shader_value_v(
                shader, self.locations[name], rl.ffi.cast("void *", buffer),
                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4, len(lights),
            )

    @contextmanager
    def scope(self, *, restore_shader: rl.Shader | None) -> Iterator[None]:
        if not self.active or self.shader is None:
            yield
            return
        rl.begin_shader_mode(self.shader)
        try:
            yield
        finally:
            # The enclosing world pass uses alpha testing, including after exceptions.
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
        self.locations.clear()
        self.active = False
