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

if TYPE_CHECKING:
    from ..world.context import WorldRenderCtx

MAX_PRESSURE_FRONTS = 16


class PressureFront(msgspec.Struct, frozen=True):
    center: Vec2
    radius: Vec2
    strength: float


def collect_pressure_fronts(ctx: WorldRenderCtx) -> list[PressureFront]:
    fronts = []
    for visual in ctx.frame.state.effects.explosion_visuals:
        ring = visual.active_ring
        if ring is None:
            continue
        fronts.append(
            PressureFront(
                ctx.view.world_to_screen(ring.pos),
                Vec2(ring.half_width, ring.half_height).mul_components(ctx.view.view_scale) * ring.scale,
                ring.color.a,
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

_PRESSURE_FRAGMENT = """#version 330
in vec2 fragTexCoord;
out vec4 finalColor;
uniform sampler2D texture0;
uniform vec2 u_size;
uniform int u_count;
uniform vec4 u_fronts[16];
uniform float u_strength[16];
void main() {
    vec2 uv = fragTexCoord;
    vec2 pixel = vec2(uv.x, 1.0 - uv.y) * u_size;
    vec2 displacement = vec2(0.0);
    float contrast = 0.0;
    for (int i = 0; i < u_count; i++) {
        vec2 delta = pixel - u_fronts[i].xy;
        vec2 radius = max(u_fronts[i].zw, vec2(1.0));
        float radial = length(delta / radius);
        float distance = (radial - 1.0) * min(radius.x, radius.y);
        float width = max(1.5, min(radius.x, radius.y) * 0.018);
        float x = distance / width;
        float crest = exp(-0.5 * x * x);
        vec2 normal = normalize(delta / (radius * radius) + vec2(1e-10));
        displacement += normal * (-x * crest) * (2.2 * u_strength[i]);
        contrast += u_strength[i] * (0.10 * crest - 0.08 * exp(-pow((distance + width) / width, 2.0)));
    }
    displacement = clamp(displacement, vec2(-6.0), vec2(6.0));
    vec2 offset = vec2(displacement.x, -displacement.y) / u_size;
    vec3 color = texture(texture0, clamp(uv + offset, 0.5 / u_size, 1.0 - 0.5 / u_size)).rgb;
    finalColor = vec4(color * (1.0 + clamp(contrast, -0.15, 0.15)), 1.0);
}
"""


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
        strength_buffer = rl.ffi.new("float[]", [f.strength for f in fronts])
        rl.set_shader_value_v(
            shader,
            self.locations["u_strength"],
            rl.ffi.cast("void *", strength_buffer),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
            len(fronts),
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
