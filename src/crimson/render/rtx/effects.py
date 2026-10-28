"""Analytic glow, shell, plasma and ion-arc draws. No simulation state."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from enum import IntEnum

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rd, rl
from grim.shaders import _shader_scope, set_world_light

from ...effects_atlas import EffectId
from .shaders import glsl


class EffectShape(IntEnum):
    GLOW = 0
    AURA = 1
    RING = 2
    PLASMA = 3
    ION_ARC = 4
    PULSE = 5
    BURST = 6


SPRITE_SHAPES = {
    EffectId.GLOW: EffectShape.GLOW, EffectId.AURA: EffectShape.AURA,
    EffectId.RING: EffectShape.RING,
}
_VERTEX = """#version 330
in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;
uniform mat4 mvp;
out vec2 fragTexCoord;
out vec4 fragColor;
out float fragShape;
void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    fragShape = vertexPosition.z;
    gl_Position = mvp * vec4(vertexPosition.xy, 0., 1.);
}
"""


class _EffectShader(msgspec.Struct, frozen=True):
    shader: rl.Shader
    kind: int
    params: int
    in_world: int


_shader: _EffectShader | None = None


def _require_shader() -> _EffectShader:
    global _shader
    if _shader is None:
        shader = rl.load_shader_from_memory(_VERTEX, glsl("effect.frag"))
        if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
            raise RuntimeError("RTX analytic effect shader failed to compile")
        rl.set_shader_value(
            shader,
            rl.get_shader_location(shader, "colDiffuse"),
            rl.ffi.new("float[4]", [1.0, 1.0, 1.0, 1.0]),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
        )
        _shader = _EffectShader(
            shader,
            rl.get_shader_location(shader, "u_kind"),
            rl.get_shader_location(shader, "u_params"),
            rl.get_shader_location(shader, "u_in_world"),
        )
    return _shader


def _parameters(data: _EffectShader, shape: EffectShape, params: tuple[float, ...]) -> None:
    rl.set_shader_value(
        data.shader, data.kind, rl.ffi.new("int *", int(shape)), rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
    )
    set_world_light(data.shader, data.in_world)
    if shape is EffectShape.PLASMA:
        buffer = rl.ffi.new("float[]", params)
        rl.set_shader_value_v(
            data.shader, data.params, rl.ffi.cast("void *", buffer), rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4, 3,
        )


def _vertices(
    center: Vec2,
    axis: Vec2,
    bounds: tuple[float, float, float, float],
    uv: tuple[float, float, float, float],
    color: RGBA,
    arc: float = 0.0,
) -> None:
    tint = color.to_rl()
    side = axis.perp_left()
    x0, y0, x1, y1 = bounds
    u0, v0, u1, v1 = uv
    rl.rl_set_texture(0)
    rl.rl_begin(rd.RL_QUADS)
    rl.rl_color4ub(tint.r, tint.g, tint.b, tint.a)
    for x, y, u, v in ((x0, y0, u0, v0), (x0, y1, u0, v1), (x1, y1, u1, v1), (x1, y0, u1, v0)):
        pos = center + axis * x + side * y
        rl.rl_tex_coord2f(u, v)
        rl.rl_vertex3f(pos.x, pos.y, arc)
    rl.rl_end()


class SpriteBatch:
    """Consecutive radial sprites share uniforms and retain per-vertex tints.

    End before texture, blend, target, or parameterized-effect changes.
    """

    def __init__(self) -> None:
        self.kind: EffectShape | None = None
        self.scope: ExitStack | None = None

    def begin(self, shape: EffectShape) -> None:
        if self.kind is shape:
            return
        self.end()
        data = _require_shader()
        self.scope = ExitStack()
        self.scope.enter_context(_shader_scope(data.shader, alpha_test=False))
        self.kind = shape
        _parameters(data, shape, ())

    def end(self) -> None:
        if self.scope is not None:
            self.scope.close()
            self.scope = None
            self.kind = None


@contextmanager
def sprite_batch() -> Generator[SpriteBatch]:
    batch = SpriteBatch()
    try:
        yield batch
    finally:
        batch.end()


def _draw(
    shape: EffectShape,
    center: Vec2,
    axis: Vec2,
    bounds: tuple[float, float, float, float],
    uv: tuple[float, float, float, float],
    color: RGBA,
    params: tuple[float, ...] = (0.0,) * 12,
    arc: float = 0.0,
) -> None:
    data = _require_shader()
    with _shader_scope(data.shader, alpha_test=False):
        _parameters(data, shape, params)
        _vertices(center, axis, bounds, uv, color, arc)


def draw_sprite(
    shape: EffectShape,
    *,
    center: Vec2,
    width: float,
    height: float,
    color: RGBA,
    rotation: float = 0.0,
    batch: SpriteBatch | None = None,
) -> None:
    if width <= 0.0 or height <= 0.0 or color.a <= 0.0:
        return
    bounds = (-width * 0.5, -height * 0.5, width * 0.5, height * 0.5)
    uv = (-1.0, -1.0, 1.0, 1.0)
    axis = Vec2.from_angle(rotation)
    if batch is not None:
        batch.begin(shape)
        _vertices(center, axis, bounds, uv, color)
    else:
        _draw(shape, center, axis, bounds, uv, color)


def draw_plasma(
    *,
    center: Vec2,
    tail_axis: Vec2,
    segments: int,
    step: float,
    tail_radius: float,
    head_radius: float,
    head_alpha: float,
    aura_radius: float,
    aura_alpha: float,
    alpha: float,
    color: tuple[float, float, float],
) -> None:
    # The local +x axis follows travel; individual native glow stamps are unrotated.
    axis = tail_axis * -1.0
    radius = max(tail_radius, head_radius, aura_radius)
    tail = max(0.0, (segments - 0.5) * step)
    bounds = (-tail - radius, -radius, radius + step * 0.5, radius)
    byte = lambda value: RGBA(a=value).to_rl().a / 255.0
    params = (
        tail_radius,
        head_radius,
        aura_radius,
        segments * step,
        step,
        byte(alpha * 0.4),
        byte(alpha * head_alpha),
        byte(alpha * aura_alpha),
        axis.x,
        axis.y,
        0.0,
        0.0,
    )
    _draw(EffectShape.PLASMA, center, axis, bounds, bounds, RGBA(*color, 1.0), params)


def draw_ion_arc(
    *, start: Vec2, end: Vec2, effect_scale: float, alpha: float, capped: bool, batch: SpriteBatch | None = None,
) -> None:
    axis, length = (end - start).normalized_with_length()
    if length <= 1e-3:
        return
    # Corners in strip scales, and per vertex the length in them (negative for the native cut), so arcs batch.
    radius = 16.0 * effect_scale
    reach = length / effect_scale
    bounds = (-radius, -radius, length + radius, radius)
    uv = (-16.0, -16.0, reach + 16.0, 16.0)
    color, arc = RGBA(0.5, 0.6, 1.0, alpha), reach if capped else -reach
    if batch is not None:
        batch.begin(EffectShape.ION_ARC)
        _vertices(start, axis, bounds, uv, color, arc)
    else:
        _draw(EffectShape.ION_ARC, start, axis, bounds, uv, color, arc=arc)
