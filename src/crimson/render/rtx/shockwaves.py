"""Thin, non-emissive explosion pressure fronts, composited in HDR before display tonemapping."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.blend import opaque_blend
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.texture_mode import texture_mode

from .explosion_shell import explosion_shell
from .shaders import glsl

if TYPE_CHECKING:
    from ..world.context import WorldRenderCtx

MAX_PRESSURE_FRONTS = 16


class PressureFront(msgspec.Struct, frozen=True):
    center: Vec2
    radius: Vec2
    strength: float


def collect_pressure_fronts(ctx: WorldRenderCtx) -> list[PressureFront]:
    fronts = []
    # Rocket fireballs light their impact with native timing, without the
    # retained explosion profile's additional pressure shell or refraction.
    for visual in ctx.frame.state.effects.explosion_visuals:
        shell = (
            explosion_shell(visual.age, visual.scale) if visual.emit_light and visual.ring_spawned else None
        )
        if shell is None:
            continue
        fronts.append(
            PressureFront(
                ctx.view.world_to_screen(visual.pos),
                ctx.view.view_scale * shell.radius,
                shell.strength,
            ),
        )
    return fronts[-MAX_PRESSURE_FRONTS:]


_PRESSURE_VERTEX = """#version 330
in vec3 vertexPosition;
in vec2 vertexTexCoord;
out vec2 fragTexCoord;
uniform mat4 mvp;
void main() {
    fragTexCoord = vertexTexCoord;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

_PRESSURE_FRAGMENT = glsl("pressure.frag")


class ShockwaveRenderer(msgspec.Struct):
    shader: rl.Shader | None = None
    target: rl.RenderTexture | None = None
    locations: dict[str, int] = msgspec.field(default_factory=dict)

    def apply(self, source: rl.Texture, fronts: Sequence[PressureFront], *, out_size: Vec2) -> rl.Texture:
        if not fronts:
            return source
        width, height = int(source.width), int(source.height)
        if self.shader is None:
            shader = rl.load_shader_from_memory(_PRESSURE_VERTEX, _PRESSURE_FRAGMENT)
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("pressure-front shader compilation failed")
            self.shader = shader
            self.locations = {
                name: int(rl.get_shader_location(shader, name))
                for name in ("u_size", "u_count", "u_fronts", "u_strength")
            }
        if self.target is None or self.target.texture.width != width or self.target.texture.height != height:
            if self.target is not None:
                rl.unload_render_texture(self.target)
            self.target = load_float_render_texture(width, height)
        shader = self.shader
        fronts = fronts[-MAX_PRESSURE_FRONTS:]
        scale = Vec2(width / out_size.x, height / out_size.y)
        values = [
            v
            for front in fronts
            for v in (
                front.center.x * scale.x,
                front.center.y * scale.y,
                front.radius.x * scale.x,
                front.radius.y * scale.y,
            )
        ]
        rl.rl_draw_render_batch_active()
        size_buffer = rl.ffi.new("float[2]", [width, height])
        rl.set_shader_value(
            shader,
            self.locations["u_size"],
            rl.ffi.cast("void *", size_buffer),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
        rl.set_shader_value(
            shader,
            self.locations["u_count"],
            rl.ffi.new("int *", len(fronts)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )
        front_buffer = rl.ffi.new("float[]", values)
        rl.set_shader_value_v(
            shader,
            self.locations["u_fronts"],
            rl.ffi.cast("void *", front_buffer),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
            len(fronts),
        )
        strengths = [f.strength for f in fronts]
        strength_buffer = rl.ffi.new("float[]", strengths + [0.0] * (-len(strengths) % 4))
        rl.set_shader_value_v(
            shader,
            self.locations["u_strength"],
            rl.ffi.cast("void *", strength_buffer),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
            (len(fronts) + 3) // 4,
        )
        with texture_mode(self.target):
            rl.begin_shader_mode(shader)
            try:
                with opaque_blend():
                    rl.draw_texture_pro(
                        source,
                        rl_rectangle(0, 0, width, -height),
                        rl_rectangle(0, 0, width, height),
                        rl_vector2(0, 0),
                        0,
                        rl.WHITE,
                    )
            finally:
                rl.end_shader_mode()
        return self.target.texture

    def close(self) -> None:
        if self.target is not None:
            rl.unload_render_texture(self.target)
            self.target = None
        if self.shader is not None:
            rl.unload_shader(self.shader)
            self.shader = None
        self.locations.clear()
