"""Owned shader resources for analytical bonus shells and lit foil emblems."""

from __future__ import annotations

from collections.abc import Generator, Sequence
from contextlib import contextmanager

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from .bonus_shaders import BONUS_FRAGMENT, BONUS_VERTEX
from .light_uniforms import LIGHT_UNIFORMS, upload_material_lights
from .material_lights import MaterialLight


class BonusLighting(msgspec.Struct):
    shader: rl.Shader | None = None
    locations: dict[str, int] = msgspec.field(default_factory=dict)

    def ensure_shader(self) -> rl.Shader:
        if self.shader is None:
            shader = rl.load_shader_from_memory(BONUS_VERTEX, BONUS_FRAGMENT)
            if int(shader.id) <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX bonus lighting shader compilation failed")
            self.shader = shader
            self.locations = {
                name: int(rl.get_shader_location(shader, name))
                for name in (*LIGHT_UNIFORMS, "u_pass", "u_grid", "u_shell_center")
            }
        return self.shader

    def prepare(self, lights: Sequence[MaterialLight], *, camera: Vec2, view_scale: Vec2) -> None:
        shader = self.ensure_shader()
        upload_material_lights(shader, self.locations, lights, camera=camera, view_scale=view_scale)

    @contextmanager
    def pass_scope(
        self,
        *,
        pass_id: int,
        shell_center: Vec2,
        grid: tuple[float, float],
        restore_shader: rl.Shader | None,
    ) -> Generator[None]:
        shader = self.ensure_shader()
        rl.rl_draw_render_batch_active()
        rl.set_shader_value(
            shader,
            self.locations["u_pass"],
            rl.ffi.new("int *", int(pass_id)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        g_buf = rl.ffi.new("float[2]", [float(grid[0]), float(grid[1])])
        rl.set_shader_value(
            shader,
            self.locations["u_grid"],
            rl.ffi.cast("void *", g_buf),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
        center = rl.ffi.new("float[2]", [shell_center.x, shell_center.y])
        rl.set_shader_value(
            shader,
            self.locations["u_shell_center"],
            rl.ffi.cast("void *", center),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
        rl.begin_shader_mode(shader)
        try:
            yield
        finally:
            rl.rl_draw_render_batch_active()
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
        self.locations.clear()
