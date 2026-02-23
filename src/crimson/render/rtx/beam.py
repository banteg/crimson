from __future__ import annotations

from dataclasses import dataclass

from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

SHADER_STAMP_ANALYTIC_RADIUS_SCALE = 16.0
SHADER_STAMP_VIRTUAL_PROFILE_A = 1.3
SHADER_STAMP_VIRTUAL_PROFILE_LINEAR = -4.8
SHADER_STAMP_VIRTUAL_PROFILE_QUAD = 1.0
SHADER_STAMP_VIRTUAL_PROFILE_OFFSET = 0.01
SHADER_STAMP_VIRTUAL_INTENSITY_GAIN = 0.92
SHADER_STAMP_VIRTUAL_CORE_FLAT_STEP_FRACTION = 0.0
SHADER_STAMP_VIRTUAL_CORE_SUPPORT_WEIGHT = 0.0
SHADER_STAMP_VIRTUAL_MAX_STAMPS = 128
SHADER_STAMP_VIRTUAL_HEAD_RADIUS_MULTIPLIER = 1.05
SHADER_STAMP_VIRTUAL_HEAD_FIRE_RADIUS_MULTIPLIER = 1.35

_BEAM_SHADER_VS_330 = """
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;
out vec2 fragTexCoord;
out vec4 fragColor;
out float fragLen;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    fragLen = vertexPosition.z;
    gl_Position = mvp * vec4(vertexPosition.x, vertexPosition.y, 0.0, 1.0);
}
"""

_BEAM_FAST_STAMPED_FS_330 = f"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;

uniform vec4 colDiffuse;
uniform float u_step_uv;
uniform float u_stamp_scale;
uniform float u_stamp_decay;
uniform float u_stamp_quad;
uniform float u_stamp_offset;
uniform float u_intensity_gain;
uniform float u_core_flat_step_fraction;
uniform float u_core_support_weight;

out vec4 finalColor;

void main() {{
    float u_len = fragLen;
    float gain = max(u_intensity_gain, 0.0);

    if (u_len < 0.0) {{
        float d = length(fragTexCoord);
        float profile = clamp(u_stamp_scale * exp(-u_stamp_decay * d - u_stamp_quad * d * d) - u_stamp_offset, 0.0, 1.0);
        float intensity = profile * fragColor.a * gain;
        vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
        finalColor = vec4(rgb, 1.0);
        return;
    }}

    float step_uv = max(0.001, u_step_uv);
    float len_uv = max(0.0, u_len);
    float stamp_count = floor(len_uv / step_uv) + 1.0;
    stamp_count = clamp(stamp_count, 0.0, float({SHADER_STAMP_VIRTUAL_MAX_STAMPS:d}));
    float core_flat_radius = max(0.0, u_core_flat_step_fraction) * step_uv;

    float accum = 0.0;
    const int MAX_STAMPS = {SHADER_STAMP_VIRTUAL_MAX_STAMPS:d};
    for (int i = 0; i < MAX_STAMPS; i++) {{
        float fi = float(i);
        if (fi >= stamp_count) {{
            break;
        }}
        float sx = fi * step_uv;
        if (sx >= len_uv) {{
            break;
        }}
        float t = clamp(sx / max(1e-6, len_uv), 0.0, 1.0);
        float d = length(vec2(fragTexCoord.x - sx, fragTexCoord.y));
        float d_eff = max(0.0, d - core_flat_radius);
        float profile = clamp(u_stamp_scale * exp(-u_stamp_decay * d_eff - u_stamp_quad * d_eff * d_eff) - u_stamp_offset, 0.0, 1.0);
        accum += t * profile;
    }}

    float core_support = max(0.0, u_core_support_weight);
    if (core_support > 0.0) {{
        float t_frag = clamp(fragTexCoord.x / max(1e-6, len_uv), 0.0, 1.0);
        float inside_body = step(0.0, fragTexCoord.x) * step(fragTexCoord.x, len_uv);
        float center_d = max(0.0, abs(fragTexCoord.y) - core_flat_radius);
        float center_profile = clamp(
            u_stamp_scale * exp(-u_stamp_decay * center_d - u_stamp_quad * center_d * center_d) - u_stamp_offset,
            0.0,
            1.0
        );
        accum = max(accum, inside_body * (core_support * t_frag * center_profile));
    }}

    float intensity = accum * fragColor.a * gain;
    vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
    finalColor = vec4(rgb, 1.0);
}}
"""


@dataclass(frozen=True, slots=True)
class _BeamFastStampedShader:
    shader: rl.Shader
    color_loc: int
    step_uv_loc: int
    stamp_scale_loc: int
    stamp_decay_loc: int
    stamp_quad_loc: int
    stamp_offset_loc: int
    intensity_gain_loc: int
    core_flat_step_fraction_loc: int
    core_support_weight_loc: int


_BEAM_FAST_STAMPED_SHADER_TRIED = False
_BEAM_FAST_STAMPED_SHADER: _BeamFastStampedShader | None = None


def _set_shader_float(shader: rl.Shader, location: int, value: float) -> None:
    if int(location) < 0:
        return
    rl.set_shader_value(
        shader,
        int(location),
        rl.ffi.new("float *", float(value)),
        rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
    )


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
        step_uv_loc=int(rl.get_shader_location(shader, "u_step_uv")),
        stamp_scale_loc=int(rl.get_shader_location(shader, "u_stamp_scale")),
        stamp_decay_loc=int(rl.get_shader_location(shader, "u_stamp_decay")),
        stamp_quad_loc=int(rl.get_shader_location(shader, "u_stamp_quad")),
        stamp_offset_loc=int(rl.get_shader_location(shader, "u_stamp_offset")),
        intensity_gain_loc=int(rl.get_shader_location(shader, "u_intensity_gain")),
        core_flat_step_fraction_loc=int(rl.get_shader_location(shader, "u_core_flat_step_fraction")),
        core_support_weight_loc=int(rl.get_shader_location(shader, "u_core_support_weight")),
    )
    return _BEAM_FAST_STAMPED_SHADER


def _require_beam_fast_stamped_shader() -> _BeamFastStampedShader:
    shader_data = _get_beam_fast_stamped_shader()
    if shader_data is None:
        raise RuntimeError("rtx mode requires beam virtual shader, but it failed to load/compile")
    return shader_data


def _apply_virtual_beam_uniforms(*, shader_data: _BeamFastStampedShader, step_uv: float, intensity_gain: float) -> None:
    shader = shader_data.shader
    _set_shader_vec4(shader, shader_data.color_loc, 1.0, 1.0, 1.0, 1.0)
    _set_shader_float(shader, shader_data.step_uv_loc, float(step_uv))
    _set_shader_float(shader, shader_data.stamp_scale_loc, float(SHADER_STAMP_VIRTUAL_PROFILE_A))
    _set_shader_float(shader, shader_data.stamp_decay_loc, float(-SHADER_STAMP_VIRTUAL_PROFILE_LINEAR))
    _set_shader_float(shader, shader_data.stamp_quad_loc, float(SHADER_STAMP_VIRTUAL_PROFILE_QUAD))
    _set_shader_float(shader, shader_data.stamp_offset_loc, float(SHADER_STAMP_VIRTUAL_PROFILE_OFFSET))
    _set_shader_float(shader, shader_data.intensity_gain_loc, float(intensity_gain))
    _set_shader_float(
        shader,
        shader_data.core_flat_step_fraction_loc,
        float(SHADER_STAMP_VIRTUAL_CORE_FLAT_STEP_FRACTION),
    )
    _set_shader_float(
        shader,
        shader_data.core_support_weight_loc,
        float(SHADER_STAMP_VIRTUAL_CORE_SUPPORT_WEIGHT),
    )


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
) -> bool:
    shader_data = _require_beam_fast_stamped_shader()

    span_units = max(0.0, float(span_dist_units))
    if span_units <= 1e-6:
        return True

    ray = head_screen - origin_screen
    direction_screen, ray_len = ray.normalized_with_length()
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

    shader = shader_data.shader
    rl.begin_shader_mode(shader)
    _apply_virtual_beam_uniforms(
        shader_data=shader_data,
        step_uv=float(step_uv),
        intensity_gain=float(SHADER_STAMP_VIRTUAL_INTENSITY_GAIN),
    )
    rl.rl_set_texture(0)
    rl.rl_begin(rd.RL_QUADS)

    def push(pos: Vec2, *, uv_x: float, uv_y: float) -> None:
        rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
        rl.rl_tex_coord2f(float(uv_x), float(uv_y))
        rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

    push(tail_end - side, uv_x=-1.0, uv_y=-1.0)
    push(tail_end + side, uv_x=-1.0, uv_y=1.0)
    push(head_end + side, uv_x=u_len + 1.0, uv_y=1.0)
    push(head_end - side, uv_x=u_len + 1.0, uv_y=-1.0)

    rl.rl_end()
    rl.rl_set_texture(0)
    rl.end_shader_mode()
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
) -> bool:
    shader_data = _require_beam_fast_stamped_shader()

    alpha_u8 = int(clamp(float(base_alpha) * 255.0, 0.0, 255.0) + 0.5)
    if alpha_u8 <= 0:
        return True

    radius_multiplier = (
        float(SHADER_STAMP_VIRTUAL_HEAD_FIRE_RADIUS_MULTIPLIER)
        if bool(is_fire)
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

    shader = shader_data.shader
    rl.begin_shader_mode(shader)
    _apply_virtual_beam_uniforms(
        shader_data=shader_data,
        step_uv=1.0,
        intensity_gain=float(SHADER_STAMP_VIRTUAL_INTENSITY_GAIN),
    )
    rl.rl_set_texture(0)
    rl.rl_begin(rd.RL_QUADS)

    def push(pos: Vec2, *, uv_x: float, uv_y: float) -> None:
        rl.rl_color4ub(int(r), int(g), int(b), int(alpha_u8))
        rl.rl_tex_coord2f(float(uv_x), float(uv_y))
        rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

    push(center_screen - forward - side, uv_x=-1.0, uv_y=-1.0)
    push(center_screen - forward + side, uv_x=-1.0, uv_y=1.0)
    push(center_screen + forward + side, uv_x=1.0, uv_y=1.0)
    push(center_screen + forward - side, uv_x=1.0, uv_y=-1.0)

    rl.rl_end()
    rl.rl_set_texture(0)
    rl.end_shader_mode()
    return True


__all__ = ["draw_beam_fast_stamped_body", "draw_beam_fast_stamped_head"]
