from __future__ import annotations

import msgspec

from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from .shaders import glsl

SHADER_STAMP_ANALYTIC_RADIUS_SCALE = 16.0
SHADER_STAMP_VIRTUAL_HEAD_RADIUS_MULTIPLIER = 1.05
SHADER_STAMP_VIRTUAL_HEAD_FIRE_RADIUS_MULTIPLIER = 1.35

_BEAM_SHADER_VS_330 = """
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec3 vertexNormal;
in vec4 vertexColor;
out vec2 fragTexCoord;
out vec4 fragColor;
out float fragLen;
flat out float fragStep;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    fragLen = vertexPosition.z;
    fragStep = vertexNormal.x;
    gl_Position = mvp * vec4(vertexPosition.x, vertexPosition.y, 0.0, 1.0);
}
"""

_BEAM_FAST_STAMPED_FS_330 = glsl("beam.frag")


class _BeamFastStampedShader(msgspec.Struct, frozen=True):
    shader: rl.Shader
    color_loc: int


_BEAM_FAST_STAMPED_SHADER_TRIED = False
_BEAM_FAST_STAMPED_SHADER: _BeamFastStampedShader | None = None


def _set_shader_vec4(shader: rl.Shader, location: int, x: float, y: float, z: float, w: float) -> None:
    if int(location) < 0:
        return
    values = rl.ffi.new("float[4]", [float(x), float(y), float(z), float(w)])
    rl.set_shader_value(
        shader,
        int(location),
        values,
        rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
    )


def _get_beam_fast_stamped_shader() -> _BeamFastStampedShader | None:
    global _BEAM_FAST_STAMPED_SHADER_TRIED, _BEAM_FAST_STAMPED_SHADER
    if _BEAM_FAST_STAMPED_SHADER_TRIED:
        return _BEAM_FAST_STAMPED_SHADER

    _BEAM_FAST_STAMPED_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_FAST_STAMPED_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_FAST_STAMPED_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_FAST_STAMPED_SHADER = None
        return None

    _BEAM_FAST_STAMPED_SHADER = _BeamFastStampedShader(
        shader=shader,
        color_loc=int(rl.get_shader_location(shader, "colDiffuse")),
    )
    return _BEAM_FAST_STAMPED_SHADER


def _require_beam_fast_stamped_shader() -> _BeamFastStampedShader:
    shader_data = _get_beam_fast_stamped_shader()
    if shader_data is None:
        raise RuntimeError("rtx mode requires beam virtual shader, but it failed to load/compile")
    return shader_data


def _apply_virtual_beam_uniforms(*, shader_data: _BeamFastStampedShader) -> None:
    _set_shader_vec4(shader_data.shader, shader_data.color_loc, 1.0, 1.0, 1.0, 1.0)


class BeamBatch:
    """Keep consecutive analytic quads in one draw, preserving their submission order.

    Stamp spacing travels per vertex, so every body and head shares the same
    uniforms. End the batch before drawing with another shader or changing
    blend modes. Like the standalone beam draws, end() restores raylib's
    default shader.
    """

    def __init__(self) -> None:
        self.active = False

    def begin(self, shader_data: _BeamFastStampedShader) -> None:
        if not self.active:
            rl.begin_shader_mode(shader_data.shader)
            _apply_virtual_beam_uniforms(shader_data=shader_data)
            self.active = True

    def end(self) -> None:
        if self.active:
            rl.end_shader_mode()
            self.active = False


def draw_beam_fast_stamped_body(
    *,
    origin_screen: Vec2,
    head_screen: Vec2,
    start_dist_units: float,
    span_dist_units: float,
    step_units: float,
    effect_scale: float,
    scale: float,
    base_alpha: float,
    streak_rgb: tuple[float, float, float],
    batch: BeamBatch | None = None,
) -> bool:
    shader_data = _require_beam_fast_stamped_shader()

    span_units = max(0.0, float(span_dist_units))
    if span_units <= 1e-6:
        return True

    ray = head_screen - origin_screen
    _direction_screen, ray_len = ray.normalized_with_length()
    if ray_len <= 1e-6:
        return True

    total_units = max(1e-6, float(start_dist_units) + span_units)
    start_t = clamp(float(start_dist_units) / total_units, 0.0, 1.0)
    p0 = origin_screen + ray * start_t
    p1 = head_screen
    direction, length = (p1 - p0).normalized_with_length()
    if length <= 1e-6:
        return True

    radius = max(0.001, float(SHADER_STAMP_ANALYTIC_RADIUS_SCALE) * float(effect_scale) * float(scale))
    screen_per_unit = float(length) / max(1e-6, span_units)
    step_screen = max(1e-6, float(step_units) * float(screen_per_unit))
    step_uv = max(1e-4, float(step_screen) / float(radius))
    u_len = float(length) / float(radius)

    side = direction.perp_left() * radius
    tail_end = p0 - direction * radius
    head_end = p1 + direction * radius

    alpha_u8 = int(clamp(float(base_alpha) * 255.0, 0.0, 255.0) + 0.5)
    if alpha_u8 <= 0:
        return True

    r = int(clamp(float(streak_rgb[0]) * 255.0, 0.0, 255.0) + 0.5)
    g = int(clamp(float(streak_rgb[1]) * 255.0, 0.0, 255.0) + 0.5)
    b = int(clamp(float(streak_rgb[2]) * 255.0, 0.0, 255.0) + 0.5)

    quads = batch or BeamBatch()
    quads.begin(shader_data)
    rl.rl_set_texture(0)
    rl.rl_begin(rd.RL_QUADS)
    rl.rl_normal3f(float(step_uv), 0.0, 0.0)

    pos = tail_end - side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(-1.0, -1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

    pos = tail_end + side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(-1.0, 1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

    pos = head_end + side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(float(u_len + 1.0), 1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

    pos = head_end - side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(float(u_len + 1.0), -1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

    rl.rl_end()
    rl.rl_set_texture(0)
    if batch is None:
        quads.end()
    return True


def draw_beam_fast_stamped_head(
    *,
    center_screen: Vec2,
    rotation_rad: float,
    effect_scale: float,
    scale: float,
    base_alpha: float,
    head_rgb: tuple[float, float, float],
    is_fire: bool,
    batch: BeamBatch | None = None,
) -> bool:
    shader_data = _require_beam_fast_stamped_shader()

    alpha_u8 = int(clamp(float(base_alpha) * 255.0, 0.0, 255.0) + 0.5)
    if alpha_u8 <= 0:
        return True

    radius_multiplier = (
        float(SHADER_STAMP_VIRTUAL_HEAD_FIRE_RADIUS_MULTIPLIER)
        if is_fire
        else float(SHADER_STAMP_VIRTUAL_HEAD_RADIUS_MULTIPLIER)
    )
    radius = max(
        0.001,
        float(SHADER_STAMP_ANALYTIC_RADIUS_SCALE) * float(effect_scale) * float(scale) * float(radius_multiplier),
    )
    direction = Vec2.from_angle(float(rotation_rad))
    side = direction.perp_left() * radius
    forward = direction * radius

    r = int(clamp(float(head_rgb[0]) * 255.0, 0.0, 255.0) + 0.5)
    g = int(clamp(float(head_rgb[1]) * 255.0, 0.0, 255.0) + 0.5)
    b = int(clamp(float(head_rgb[2]) * 255.0, 0.0, 255.0) + 0.5)

    quads = batch or BeamBatch()
    quads.begin(shader_data)
    rl.rl_set_texture(0)
    rl.rl_begin(rd.RL_QUADS)

    pos = center_screen - forward - side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(-1.0, -1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

    pos = center_screen - forward + side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(-1.0, 1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

    pos = center_screen + forward + side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(1.0, 1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

    pos = center_screen + forward - side
    rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
    rl.rl_tex_coord2f(1.0, -1.0)
    rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

    rl.rl_end()
    rl.rl_set_texture(0)
    if batch is None:
        quads.end()
    return True


__all__ = ["BeamBatch", "draw_beam_fast_stamped_body", "draw_beam_fast_stamped_head"]
