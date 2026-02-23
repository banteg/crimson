from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from grim.assets import TextureLoader, find_paq_path, resolve_asset_path
from grim.color import RGBA
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl
from grim.view import View, ViewContext

from ..effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID, EffectId
from ..paths import default_runtime_dir
from ..projectiles import ProjectileTypeId
from ..render.projectile_draw.beam_sampling import BeamSamplePlan, build_beam_sample_plan, iter_beam_sample_offsets
from ..render.projectile_draw.common import RAD_TO_DEG
from ..render.projectile_render_registry import beam_effect_scale
from ..weapons import weapon_entry_for_projectile_type_id
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view

BG = rl.Color(12, 12, 14, 255)
GRID = rl.Color(34, 34, 42, 255)
UI_TEXT = rl.Color(232, 232, 232, 255)
UI_HINT = rl.Color(170, 170, 170, 255)
UI_ACCENT = rl.Color(255, 194, 92, 255)
UI_WARN = rl.Color(255, 150, 100, 255)
FIRE_LINE = rl.Color(255, 128, 58, 220)
ION_LINE = rl.Color(120, 168, 255, 210)
SELECTED_LINE = rl.Color(255, 255, 255, 255)
PANEL_DIVIDER = rl.Color(56, 56, 72, 255)
SEGMENT_MARK = rl.Color(255, 255, 255, 165)
HEAD_MARK = rl.Color(255, 245, 190, 255)
OVERLAY_MARK = rl.Color(255, 140, 80, 255)
CAP_START_MARK = rl.Color(255, 196, 92, 255)
ORIGIN_MARK = rl.Color(100, 220, 180, 255)

ROLLING_WINDOW_SIZE = 240
HEAD_REGION_T_MIN = 0.65
SHADER_GEMINI_2_RADIUS_SCALE = 16.0
SHADER_GEMINI_2_RADIUS_EXPAND = 1.25
SHADER_GEMINI_2_HEAD_RADIUS_MULTIPLIER = 1.05
SHADER_GEMINI_2_HEAD_FIRE_RADIUS_MULTIPLIER = 1.35
SHADER_GEMINI_2_APPROX_A_DEFAULT = 1.0607
SHADER_GEMINI_2_APPROX_B_DEFAULT = -4.8256
SHADER_GEMINI_2_APPROX_C_DEFAULT = 0.0125
SHADER_GEMINI_2_INTENSITY_GAIN_DEFAULT = 2.5

# Research reference values from decompiled texture analysis.
# Raw texture: alpha(r) ~ 0.88 * exp(-0.3 * r), UV-space: exp(-4.5 * r) - 0.011, scaled by 0.89.
SHADER_GEMINI_2_RESEARCH_PARAMS = (0.89, -4.5, 0.011, 2.5)
SHADER_GEMINI_2_APPROX_A_MIN = 0.1
SHADER_GEMINI_2_APPROX_A_MAX = 5.0
SHADER_GEMINI_2_APPROX_B_MIN = -20.0
SHADER_GEMINI_2_APPROX_B_MAX = -0.1
SHADER_GEMINI_2_APPROX_C_MIN = -1.0
SHADER_GEMINI_2_APPROX_C_MAX = 1.0
SHADER_GEMINI_2_INTENSITY_GAIN_MIN = 0.5
SHADER_GEMINI_2_INTENSITY_GAIN_MAX = 6.0
SHADER_GEMINI_2_APPROX_A_STEP = 0.05
SHADER_GEMINI_2_APPROX_B_STEP = 0.1
SHADER_GEMINI_2_APPROX_C_STEP = 0.05
SHADER_GEMINI_2_INTENSITY_GAIN_STEP = 0.05
SHADER_GEMINI_2_PROFILE_SAMPLE_COUNT = 96
SHADER_GEMINI_2_PROFILE_RING_SAMPLES = 96
SHADER_EXT_CLAUDE_LONGITUDINAL_GAMMA_DEFAULT = 1.45
SHADER_EXT_CLAUDE_RADIUS_TAPER_DEFAULT = 1.15
SHADER_EXT_CLAUDE_CORE_WEIGHT_DEFAULT = 0.7
SHADER_EXT_CLAUDE_HALO_DECAY_DEFAULT = -1.2
SHADER_EXT_CLAUDE_CAP_SOFTNESS_DEFAULT = 0.75
SHADER_EXT_GEMINI_CORE_A_DEFAULT = 1.5
SHADER_EXT_GEMINI_CORE_B_DEFAULT = -12.0
SHADER_EXT_GEMINI_TAIL_WIDTH_DEFAULT = 0.6
SHADER_EXT_GEMINI_CAP_SCALE_DEFAULT = 1.25
SHADER_EXT_GPT_PRO_COVER_LEN_DEFAULT = 1.0
SHADER_EXT_GPT_PRO_HALO_W_DEFAULT = 0.25
SHADER_GEMINI_2_COVER_LEN_DEFAULT = 1.0
SHADER_GEMINI_2_HALO_W_DEFAULT = 0.0
SHADER_GEMINI_2_CAP_SCALE_DEFAULT = 1.0
SHADER_GEMINI_2_COVER_LEN_ION_CANNON = 1.1
SHADER_GEMINI_2_HALO_W_ION_RIFLE = 0.08
SHADER_GEMINI_2_HALO_W_ION_CANNON = 0.30
BENCH_FRAMES_PER_MODE = 240
BATCH_PROBE_QUADS_DEFAULT = 4096
BATCH_PROBE_QUADS_STEP = 256
BATCH_PROBE_QUADS_MIN = 256
BATCH_PROBE_QUADS_MAX = 32768
DISTANCE_SCALE_REFERENCE_UNITS = 220.0
NATIVE_BEAM_ACTIVE_LIFE_SECONDS = 0.4
PROJECTILE_SPEED_UNITS_PER_META = 20.0
SHADER_STAMP_ANALYTIC_ALPHA_SCALE = 0.88
SHADER_STAMP_ANALYTIC_ALPHA_DECAY_PER_PX = 0.3
SHADER_STAMP_ANALYTIC_RADIUS_SCALE = 16.0
SHADER_STAMP_VIRTUAL_PROFILE_A_DEFAULT = 1.3
SHADER_STAMP_VIRTUAL_PROFILE_LINEAR_DEFAULT = -4.6
SHADER_STAMP_VIRTUAL_PROFILE_QUAD_DEFAULT = 1.0
SHADER_STAMP_VIRTUAL_PROFILE_OFFSET_DEFAULT = 0.02
SHADER_STAMP_VIRTUAL_INTENSITY_GAIN_DEFAULT = 1.0
SHADER_STAMP_VIRTUAL_CORE_FLAT_STEP_FRACTION_DEFAULT = 0.0
SHADER_STAMP_VIRTUAL_CORE_SUPPORT_WEIGHT_DEFAULT = 0.0
SHADER_STAMP_VIRTUAL_MAX_STAMPS = 128

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

_BEAM_GEMINI_2_FS_330 = """
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;

uniform vec4 colDiffuse;
uniform float u_approx_a;
uniform float u_approx_b;
uniform float u_approx_c;
uniform float u_intensity_gain;
uniform float u_step_uv;
uniform float u_cover_len;
uniform float u_halo_w;
uniform float u_cap_scale;

out vec4 finalColor;

void main() {
    float gain = max(u_intensity_gain, 0.0);
    float halo_w = max(u_halo_w, 0.0);
    float cap_scale = max(u_cap_scale, 0.0);
    float u_len = fragLen;
    if (u_len < 0.0) {
        float d = length(fragTexCoord);
        float e = exp(u_approx_b * d);
        float core = clamp(u_approx_a * e - u_approx_c, 0.0, 1.0);
        float halo = clamp(u_approx_a * sqrt(max(e, 0.0)) - u_approx_c, 0.0, 1.0);
        float shell = max(0.0, halo - core);
        float profile = clamp(core + halo_w * shell, 0.0, 1.0);
        float intensity = profile * fragColor.a * gain;
        vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
        finalColor = vec4(rgb, 1.0);
        return;
    }

    float step_uv = max(1e-4, u_step_uv);
    float x0 = min(step_uv, max(0.0, u_len));
    float residual = mod(max(0.0, u_len), step_uv);
    float end_gap = residual;
    if (end_gap <= step_uv * 1e-4) {
        end_gap = step_uv;
    }
    float x1 = max(x0, u_len - end_gap);

    float dx = max(0.0, max(x0 - fragTexCoord.x, fragTexCoord.x - x1));
    dx *= cap_scale;
    float d = length(vec2(dx, fragTexCoord.y));

    float e = exp(u_approx_b * d);
    float core = clamp(u_approx_a * e - u_approx_c, 0.0, 1.0);
    float halo = clamp(u_approx_a * sqrt(max(e, 0.0)) - u_approx_c, 0.0, 1.0);
    float shell = max(0.0, halo - core);
    float trans_profile = clamp(core + halo_w * shell, 0.0, 1.0);

    float closest_x = clamp(fragTexCoord.x, x0, x1);
    float t = clamp(closest_x / max(u_len, 1e-6), 0.0, 1.0);

    float seg_len = max(0.0, x1 - x0);
    float w = min(max(0.0, u_cover_len), 0.5 * seg_len);
    w = max(w, 1e-4);
    float left = min(max(0.0, fragTexCoord.x - x0), w);
    float right = min(max(0.0, x1 - fragTexCoord.x), w);
    float cover = clamp((left + right) / (2.0 * w), 0.0, 1.0);

    float structural_alpha = t * cover * fragColor.a;
    float intensity = trans_profile * structural_alpha * gain;
    vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
    finalColor = vec4(rgb, 1.0);
}
"""

_BEAM_STAMPED_ANALYTIC_FS_330 = f"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;

uniform vec4 colDiffuse;

out vec4 finalColor;

void main() {{
    float d = length(fragTexCoord);
    float profile = {SHADER_STAMP_ANALYTIC_ALPHA_SCALE:.8f} * exp(-{SHADER_STAMP_ANALYTIC_ALPHA_DECAY_PER_PX * SHADER_STAMP_ANALYTIC_RADIUS_SCALE:.8f} * d);
    float intensity = profile * fragColor.a;
    vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
    finalColor = vec4(rgb, 1.0);
}}
"""

_BEAM_STAMPED_VIRTUAL_FS_330 = f"""
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

    // Head pass (fragLen < 0): radial analytic cap profile.
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

    // Continuous centerline support to suppress visible stamp striping in the tail.
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

_BEAM_EXT_CLAUDE_FS_330 = """
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;

uniform vec4 colDiffuse;
uniform float u_approx_a;
uniform float u_approx_b;
uniform float u_approx_c;
uniform float u_intensity_gain;
uniform float u_longitudinal_gamma;
uniform float u_radius_taper;
uniform float u_core_weight;
uniform float u_halo_decay;
uniform float u_cap_softness;

out vec4 finalColor;

void main() {
    float gain = max(u_intensity_gain, 0.0);
    float core_w = clamp(u_core_weight, 0.0, 1.0);
    float halo_decay = min(u_halo_decay, -0.001);
    float gamma = max(0.05, u_longitudinal_gamma);
    float cap_soft = max(0.01, u_cap_softness);

    float u_len = fragLen;
    if (u_len < 0.0) {
        float d = length(fragTexCoord);
        float d_soft = d * cap_soft;
        float core = clamp(u_approx_a * exp(u_approx_b * d_soft) - u_approx_c, 0.0, 1.0);
        float halo = clamp(exp(halo_decay * d_soft), 0.0, 1.0);
        float profile = mix(halo, core, core_w);
        float intensity = profile * fragColor.a * gain;
        vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
        finalColor = vec4(rgb, 1.0);
        return;
    }

    float dx = max(0.0, max(-fragTexCoord.x, fragTexCoord.x - u_len));
    float closest_x = clamp(fragTexCoord.x, 0.0, u_len);
    float t = clamp(closest_x / max(1.0, u_len), 0.0, 1.0);
    float t_shaped = pow(t, gamma);

    float r_scale_t = 1.0 + (u_radius_taper - 1.0) * t_shaped;
    float d_body = length(vec2(dx, fragTexCoord.y / max(1e-4, r_scale_t)));

    float core = clamp(u_approx_a * exp(u_approx_b * d_body) - u_approx_c, 0.0, 1.0);
    float halo = clamp(exp(halo_decay * d_body), 0.0, 1.0);
    float trans_profile = mix(halo, core, core_w);

    float structural_alpha = t_shaped * fragColor.a;
    float intensity = trans_profile * structural_alpha * gain;
    vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
    finalColor = vec4(rgb, 1.0);
}
"""

_BEAM_EXT_GEMINI_FS_330 = """
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;

uniform vec4 colDiffuse;
uniform float u_halo_a;
uniform float u_halo_b;
uniform float u_core_a;
uniform float u_core_b;
uniform float u_approx_c;
uniform float u_intensity_gain;
uniform float u_tail_width;
uniform float u_cap_scale;

out vec4 finalColor;

void main() {
    float gain = max(u_intensity_gain, 0.0);
    float u_len = fragLen;

    if (u_len < 0.0) {
        float d = length(fragTexCoord);
        float profile = clamp(u_halo_a * exp(u_halo_b * d) - u_approx_c, 0.0, 1.0);
        float intensity = profile * fragColor.a * gain;
        vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
        finalColor = vec4(rgb, 1.0);
        return;
    }

    float closest_x = clamp(fragTexCoord.x, 0.0, u_len);
    float t = clamp(closest_x / max(1.0, u_len), 0.0, 1.0);

    float width_scale = mix(max(0.01, u_tail_width), 1.0, t);
    float dy = fragTexCoord.y / width_scale;

    float dx = max(0.0, max(-fragTexCoord.x, fragTexCoord.x - u_len));
    dx *= u_cap_scale;

    float d = length(vec2(dx, dy));
    float halo = u_halo_a * exp(u_halo_b * d);
    float core = u_core_a * exp(u_core_b * d);
    float trans_profile = clamp(halo + core - u_approx_c, 0.0, 1.0);

    float structural_alpha = t * fragColor.a;
    float intensity = trans_profile * structural_alpha * gain;
    vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
    finalColor = vec4(rgb, 1.0);
}
"""

_BEAM_EXT_GPT_PRO_FS_330 = """
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;

uniform vec4 colDiffuse;
uniform float u_approx_a;
uniform float u_approx_b;
uniform float u_approx_c;
uniform float u_intensity_gain;
uniform float u_step_uv;
uniform float u_cover_len;
uniform float u_halo_w;

out vec4 finalColor;

void main() {
    float gain = max(u_intensity_gain, 0.0);
    float halo_w = max(u_halo_w, 0.0);
    float u_len = fragLen;

    if (u_len < 0.0) {
        float d = length(fragTexCoord);
        float e = exp(u_approx_b * d);
        float core = clamp(u_approx_a * e - u_approx_c, 0.0, 1.0);
        float halo = clamp(u_approx_a * sqrt(max(e, 0.0)) - u_approx_c, 0.0, 1.0);
        float shell = max(0.0, halo - core);
        float profile = clamp(core + halo_w * shell, 0.0, 1.0);
        float intensity = profile * fragColor.a * gain;
        vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
        finalColor = vec4(rgb, 1.0);
        return;
    }

    float step_uv = max(1e-4, u_step_uv);
    float x0 = min(step_uv, max(0.0, u_len));
    float residual = mod(max(0.0, u_len), step_uv);
    float end_gap = residual;
    if (end_gap <= step_uv * 1e-4) {
        end_gap = step_uv;
    }
    float x1 = max(x0, u_len - end_gap);

    float dx = max(0.0, max(x0 - fragTexCoord.x, fragTexCoord.x - x1));
    float d = length(vec2(dx, fragTexCoord.y));

    float e = exp(u_approx_b * d);
    float core = clamp(u_approx_a * e - u_approx_c, 0.0, 1.0);
    float halo = clamp(u_approx_a * sqrt(max(e, 0.0)) - u_approx_c, 0.0, 1.0);
    float shell = max(0.0, halo - core);
    float profile = clamp(core + halo_w * shell, 0.0, 1.0);

    float xc = clamp(fragTexCoord.x, x0, x1);
    float t = clamp(xc / max(u_len, 1e-6), 0.0, 1.0);

    float seg_len = max(0.0, x1 - x0);
    float w = min(max(0.0, u_cover_len), 0.5 * seg_len);
    w = max(w, 1e-4);
    float left = min(max(0.0, fragTexCoord.x - x0), w);
    float right = min(max(0.0, x1 - fragTexCoord.x), w);
    float cover = clamp((left + right) / (2.0 * w), 0.0, 1.0);

    float structural = t * cover * fragColor.a;
    float intensity = profile * structural * gain;
    vec3 rgb = fragColor.rgb * colDiffuse.rgb * intensity;
    finalColor = vec4(rgb, 1.0);
}
"""

_BEAM_GEMINI_2_SHADER_TRIED = False
_BEAM_GEMINI_2_SHADER: rl.Shader | None = None
_BEAM_GEMINI_2_APPROX_A_LOC = -1
_BEAM_GEMINI_2_APPROX_B_LOC = -1
_BEAM_GEMINI_2_APPROX_C_LOC = -1
_BEAM_GEMINI_2_INTENSITY_GAIN_LOC = -1
_BEAM_GEMINI_2_COLOR_LOC = -1
_BEAM_GEMINI_2_STEP_UV_LOC = -1
_BEAM_GEMINI_2_COVER_LEN_LOC = -1
_BEAM_GEMINI_2_HALO_W_LOC = -1
_BEAM_GEMINI_2_CAP_SCALE_LOC = -1
_BEAM_STAMPED_ANALYTIC_SHADER_TRIED = False
_BEAM_STAMPED_ANALYTIC_SHADER: rl.Shader | None = None
_BEAM_STAMPED_ANALYTIC_COLOR_LOC = -1
_BEAM_STAMPED_VIRTUAL_SHADER_TRIED = False
_BEAM_STAMPED_VIRTUAL_SHADER: rl.Shader | None = None
_BEAM_STAMPED_VIRTUAL_COLOR_LOC = -1
_BEAM_STAMPED_VIRTUAL_STEP_UV_LOC = -1
_BEAM_STAMPED_VIRTUAL_STAMP_SCALE_LOC = -1
_BEAM_STAMPED_VIRTUAL_STAMP_DECAY_LOC = -1
_BEAM_STAMPED_VIRTUAL_STAMP_QUAD_LOC = -1
_BEAM_STAMPED_VIRTUAL_STAMP_OFFSET_LOC = -1
_BEAM_STAMPED_VIRTUAL_INTENSITY_GAIN_LOC = -1
_BEAM_STAMPED_VIRTUAL_CORE_FLAT_STEP_FRACTION_LOC = -1
_BEAM_STAMPED_VIRTUAL_CORE_SUPPORT_WEIGHT_LOC = -1
_BEAM_EXT_CLAUDE_SHADER_TRIED = False
_BEAM_EXT_CLAUDE_SHADER: rl.Shader | None = None
_BEAM_EXT_CLAUDE_COLOR_LOC = -1
_BEAM_EXT_CLAUDE_APPROX_A_LOC = -1
_BEAM_EXT_CLAUDE_APPROX_B_LOC = -1
_BEAM_EXT_CLAUDE_APPROX_C_LOC = -1
_BEAM_EXT_CLAUDE_INTENSITY_GAIN_LOC = -1
_BEAM_EXT_CLAUDE_LONGITUDINAL_GAMMA_LOC = -1
_BEAM_EXT_CLAUDE_RADIUS_TAPER_LOC = -1
_BEAM_EXT_CLAUDE_CORE_WEIGHT_LOC = -1
_BEAM_EXT_CLAUDE_HALO_DECAY_LOC = -1
_BEAM_EXT_CLAUDE_CAP_SOFTNESS_LOC = -1
_BEAM_EXT_GEMINI_SHADER_TRIED = False
_BEAM_EXT_GEMINI_SHADER: rl.Shader | None = None
_BEAM_EXT_GEMINI_COLOR_LOC = -1
_BEAM_EXT_GEMINI_HALO_A_LOC = -1
_BEAM_EXT_GEMINI_HALO_B_LOC = -1
_BEAM_EXT_GEMINI_CORE_A_LOC = -1
_BEAM_EXT_GEMINI_CORE_B_LOC = -1
_BEAM_EXT_GEMINI_APPROX_C_LOC = -1
_BEAM_EXT_GEMINI_INTENSITY_GAIN_LOC = -1
_BEAM_EXT_GEMINI_TAIL_WIDTH_LOC = -1
_BEAM_EXT_GEMINI_CAP_SCALE_LOC = -1
_BEAM_EXT_GPT_PRO_SHADER_TRIED = False
_BEAM_EXT_GPT_PRO_SHADER: rl.Shader | None = None
_BEAM_EXT_GPT_PRO_COLOR_LOC = -1
_BEAM_EXT_GPT_PRO_APPROX_A_LOC = -1
_BEAM_EXT_GPT_PRO_APPROX_B_LOC = -1
_BEAM_EXT_GPT_PRO_APPROX_C_LOC = -1
_BEAM_EXT_GPT_PRO_INTENSITY_GAIN_LOC = -1
_BEAM_EXT_GPT_PRO_STEP_UV_LOC = -1
_BEAM_EXT_GPT_PRO_COVER_LEN_LOC = -1
_BEAM_EXT_GPT_PRO_HALO_W_LOC = -1


class BeamRenderMode(str, Enum):
    BASELINE_SPRITE = "baseline_sprite"
    SHADER_STAMPED_VIRTUAL = "shader_stamped_virtual"
    SHADER_EXT_CLAUDE = "shader_ext_claude"
    SHADER_EXT_GEMINI = "shader_ext_gemini"
    SHADER_EXT_GPT_PRO = "shader_ext_gpt_pro"
    SHADER_GEMINI_2 = "shader_gemini_2"


_RENDER_MODE_ORDER: tuple[BeamRenderMode, ...] = (
    BeamRenderMode.BASELINE_SPRITE,
    BeamRenderMode.SHADER_STAMPED_VIRTUAL,
    BeamRenderMode.SHADER_EXT_CLAUDE,
    BeamRenderMode.SHADER_EXT_GEMINI,
    BeamRenderMode.SHADER_EXT_GPT_PRO,
    BeamRenderMode.SHADER_GEMINI_2,
)


def cycle_beam_render_mode(mode: BeamRenderMode) -> BeamRenderMode:
    try:
        idx = _RENDER_MODE_ORDER.index(mode)
    except ValueError:
        return BeamRenderMode.BASELINE_SPRITE
    return _RENDER_MODE_ORDER[(idx + 1) % len(_RENDER_MODE_ORDER)]


class HeadCapVariant(str, Enum):
    ORIGINAL = "original"
    BODY_CAP = "body_cap"


_HEAD_CAP_VARIANT_ORDER: tuple[HeadCapVariant, ...] = (
    HeadCapVariant.ORIGINAL,
    HeadCapVariant.BODY_CAP,
)


class BeamScenarioPreset(str, Enum):
    PLASMA_LIKE = "plasma_like"
    CROWD_STRESS = "crowd_stress"
    LONG_UNCAPPED = "long_uncapped"


@dataclass(frozen=True, slots=True)
class BeamIonPreset:
    key: str
    label: str
    projectile_type_id: int
    note: str


_ION_PRESET_ORDER: tuple[BeamIonPreset, ...] = (
    BeamIonPreset(
        key="ion_rifle",
        label="ion rifle",
        projectile_type_id=int(ProjectileTypeId.ION_RIFLE),
        note="type=0x15 (shock chain)",
    ),
    BeamIonPreset(
        key="ion_minigun",
        label="ion minigun",
        projectile_type_id=int(ProjectileTypeId.ION_MINIGUN),
        note="type=0x16 (ion shotgun pellets)",
    ),
    BeamIonPreset(
        key="ion_cannon",
        label="ion cannon",
        projectile_type_id=int(ProjectileTypeId.ION_CANNON),
        note="type=0x17",
    ),
)


@dataclass(frozen=True, slots=True)
class BeamScenarioConfig:
    projectile_count: int
    base_distance_units: float
    distance_jitter_units: float
    cap_enabled: bool
    use_fire_profile: bool
    force_life_high: bool
    distance_to_screen_scale: float = 1.0


_SCENARIO_CONFIG_BY_PRESET: dict[BeamScenarioPreset, BeamScenarioConfig] = {
    BeamScenarioPreset.PLASMA_LIKE: BeamScenarioConfig(
        projectile_count=14,
        base_distance_units=220.0,
        distance_jitter_units=80.0,
        cap_enabled=True,
        use_fire_profile=True,
        force_life_high=True,
        distance_to_screen_scale=1.0,
    ),
    BeamScenarioPreset.CROWD_STRESS: BeamScenarioConfig(
        projectile_count=64,
        base_distance_units=220.0,
        distance_jitter_units=80.0,
        cap_enabled=True,
        use_fire_profile=True,
        force_life_high=True,
        distance_to_screen_scale=1.0,
    ),
    BeamScenarioPreset.LONG_UNCAPPED: BeamScenarioConfig(
        projectile_count=32,
        base_distance_units=900.0,
        distance_jitter_units=250.0,
        cap_enabled=False,
        use_fire_profile=True,
        force_life_high=True,
        distance_to_screen_scale=1.0,
    ),
}


def beam_scenario_config(preset: BeamScenarioPreset) -> BeamScenarioConfig:
    return _SCENARIO_CONFIG_BY_PRESET[preset]


@dataclass(frozen=True, slots=True)
class BeamFrameStats:
    beam_draw_calls_total: int
    beam_draw_calls_body: int
    beam_draw_calls_head: int
    beam_draw_calls_overlay: int
    beam_draw_ms: float
    frame_ms: float


@dataclass(frozen=True, slots=True)
class BeamStatsSummary:
    sample_count: int
    avg_draw_calls_total: float
    p50_draw_calls_total: float
    p95_draw_calls_total: float
    avg_beam_draw_ms: float
    p50_beam_draw_ms: float
    p95_beam_draw_ms: float
    avg_frame_ms: float
    p50_frame_ms: float
    p95_frame_ms: float


@dataclass(frozen=True, slots=True)
class BeamShaderGemini2Params:
    approx_a: float = SHADER_GEMINI_2_APPROX_A_DEFAULT
    approx_b: float = SHADER_GEMINI_2_APPROX_B_DEFAULT
    approx_c: float = SHADER_GEMINI_2_APPROX_C_DEFAULT
    intensity_gain: float = SHADER_GEMINI_2_INTENSITY_GAIN_DEFAULT


@dataclass(frozen=True, slots=True)
class BeamShaderExtClaudeParams:
    approx_a: float = SHADER_GEMINI_2_APPROX_A_DEFAULT
    approx_b: float = SHADER_GEMINI_2_APPROX_B_DEFAULT
    approx_c: float = SHADER_GEMINI_2_APPROX_C_DEFAULT
    intensity_gain: float = SHADER_GEMINI_2_INTENSITY_GAIN_DEFAULT
    longitudinal_gamma: float = SHADER_EXT_CLAUDE_LONGITUDINAL_GAMMA_DEFAULT
    radius_taper: float = SHADER_EXT_CLAUDE_RADIUS_TAPER_DEFAULT
    core_weight: float = SHADER_EXT_CLAUDE_CORE_WEIGHT_DEFAULT
    halo_decay: float = SHADER_EXT_CLAUDE_HALO_DECAY_DEFAULT
    cap_softness: float = SHADER_EXT_CLAUDE_CAP_SOFTNESS_DEFAULT


@dataclass(frozen=True, slots=True)
class BeamShaderExtGeminiParams:
    halo_a: float = SHADER_GEMINI_2_APPROX_A_DEFAULT
    halo_b: float = SHADER_GEMINI_2_APPROX_B_DEFAULT
    core_a: float = SHADER_EXT_GEMINI_CORE_A_DEFAULT
    core_b: float = SHADER_EXT_GEMINI_CORE_B_DEFAULT
    approx_c: float = SHADER_GEMINI_2_APPROX_C_DEFAULT
    intensity_gain: float = SHADER_GEMINI_2_INTENSITY_GAIN_DEFAULT
    tail_width: float = SHADER_EXT_GEMINI_TAIL_WIDTH_DEFAULT
    cap_scale: float = SHADER_EXT_GEMINI_CAP_SCALE_DEFAULT


@dataclass(frozen=True, slots=True)
class BeamShaderExtGptProParams:
    approx_a: float = SHADER_GEMINI_2_APPROX_A_DEFAULT
    approx_b: float = SHADER_GEMINI_2_APPROX_B_DEFAULT
    approx_c: float = SHADER_GEMINI_2_APPROX_C_DEFAULT
    intensity_gain: float = SHADER_GEMINI_2_INTENSITY_GAIN_DEFAULT
    cover_len: float = SHADER_EXT_GPT_PRO_COVER_LEN_DEFAULT
    halo_w: float = SHADER_EXT_GPT_PRO_HALO_W_DEFAULT


@dataclass(frozen=True, slots=True)
class BeamSpriteReferenceProfile:
    distances_norm: tuple[float, ...]
    alpha_profile: tuple[float, ...]
    radius_px: float
    centroid_x: float
    centroid_y: float
    source: str


@dataclass(frozen=True, slots=True)
class BeamProfileMatchMetrics:
    weighted_mse: float
    mse: float
    r80_delta: float
    r50_delta: float
    score: float


@dataclass(slots=True)
class BeamModeRollingStats:
    window_size: int = ROLLING_WINDOW_SIZE
    _frames: deque[BeamFrameStats] = field(init=False)

    def __post_init__(self) -> None:
        self._frames = deque(maxlen=max(1, int(self.window_size)))

    def add(self, frame: BeamFrameStats) -> None:
        self._frames.append(frame)

    def clear(self) -> None:
        self._frames.clear()

    @property
    def sample_count(self) -> int:
        return len(self._frames)

    def summary(self) -> BeamStatsSummary | None:
        if not self._frames:
            return None

        draw_calls = [float(frame.beam_draw_calls_total) for frame in self._frames]
        draw_ms = [float(frame.beam_draw_ms) for frame in self._frames]
        frame_ms = [float(frame.frame_ms) for frame in self._frames]
        return BeamStatsSummary(
            sample_count=len(self._frames),
            avg_draw_calls_total=_mean(draw_calls),
            p50_draw_calls_total=_percentile(draw_calls, 0.5),
            p95_draw_calls_total=_percentile(draw_calls, 0.95),
            avg_beam_draw_ms=_mean(draw_ms),
            p50_beam_draw_ms=_percentile(draw_ms, 0.5),
            p95_beam_draw_ms=_percentile(draw_ms, 0.95),
            avg_frame_ms=_mean(frame_ms),
            p50_frame_ms=_percentile(frame_ms, 0.5),
            p95_frame_ms=_percentile(frame_ms, 0.95),
        )


@dataclass(frozen=True, slots=True)
class BeamDrawCounts:
    body_calls: int
    head_calls: int
    overlay_calls: int
    visible_segments: int
    head_region_segments: int

    @property
    def total_calls(self) -> int:
        return int(self.body_calls + self.head_calls + self.overlay_calls)


@dataclass(frozen=True, slots=True)
class BeamCountInput:
    plan: BeamSamplePlan | None
    life: float
    screen_length_px: float


@dataclass(frozen=True, slots=True)
class BeamRenderFrameResult:
    current_counts: BeamDrawCounts
    baseline_counts: BeamDrawCounts


@dataclass(frozen=True, slots=True)
class BatchProbeResult:
    requested_quads: int
    untextured_first_flush_quad: int | None
    untextured_flush_count: int
    textured_available: bool
    textured_first_flush_quad: int | None
    textured_flush_count: int
    elapsed_ms: float


def _clamp_shader_params(params: BeamShaderGemini2Params) -> BeamShaderGemini2Params:
    return BeamShaderGemini2Params(
        approx_a=float(clamp(params.approx_a, SHADER_GEMINI_2_APPROX_A_MIN, SHADER_GEMINI_2_APPROX_A_MAX)),
        approx_b=float(clamp(params.approx_b, SHADER_GEMINI_2_APPROX_B_MIN, SHADER_GEMINI_2_APPROX_B_MAX)),
        approx_c=float(clamp(params.approx_c, SHADER_GEMINI_2_APPROX_C_MIN, SHADER_GEMINI_2_APPROX_C_MAX)),
        intensity_gain=float(
            clamp(params.intensity_gain, SHADER_GEMINI_2_INTENSITY_GAIN_MIN, SHADER_GEMINI_2_INTENSITY_GAIN_MAX),
        ),
    )


def _shader_profile_value(distance_norm: float, params: BeamShaderGemini2Params) -> float:
    d = float(clamp(distance_norm, 0.0, 1.0))
    profile = float(clamp(params.approx_a * math.exp(params.approx_b * d) - params.approx_c, 0.0, 1.0))
    return float(profile * max(0.0, float(params.intensity_gain)))


def _normalize_profile(values: Sequence[float]) -> tuple[float, ...]:
    if not values:
        return ()
    peak = max(float(v) for v in values)
    if peak <= 1e-9:
        return tuple(0.0 for _ in values)
    return tuple(float(v) / float(peak) for v in values)


def _radius_at_level(distances_norm: Sequence[float], values_norm: Sequence[float], *, level: float) -> float:
    if not distances_norm or not values_norm:
        return 0.0
    level = float(clamp(level, 0.0, 1.0))
    prev_d = float(distances_norm[0])
    prev_v = float(values_norm[0])
    if prev_v <= level:
        return float(prev_d)
    for i in range(1, min(len(distances_norm), len(values_norm))):
        curr_d = float(distances_norm[i])
        curr_v = float(values_norm[i])
        if curr_v <= level:
            span = curr_v - prev_v
            if abs(span) <= 1e-9:
                return float(curr_d)
            t = (level - prev_v) / span
            return float(prev_d * (1.0 - t) + curr_d * t)
        prev_d = curr_d
        prev_v = curr_v
    return float(distances_norm[min(len(distances_norm), len(values_norm)) - 1])


def _profile_match_metrics(
    *,
    reference_distances: Sequence[float],
    reference_profile: Sequence[float],
    params: BeamShaderGemini2Params,
) -> BeamProfileMatchMetrics:
    count = min(len(reference_distances), len(reference_profile))
    if count <= 0:
        return BeamProfileMatchMetrics(weighted_mse=0.0, mse=0.0, r80_delta=0.0, r50_delta=0.0, score=0.0)

    distances = tuple(float(reference_distances[i]) for i in range(count))
    ref_values = tuple(float(reference_profile[i]) for i in range(count))
    ref_norm = _normalize_profile(ref_values)
    model_values = tuple(_shader_profile_value(d, params) for d in distances)
    model_norm = _normalize_profile(model_values)

    mse_sum = 0.0
    weighted_sum = 0.0
    weight_total = 0.0
    for d, ref, model in zip(distances, ref_norm, model_norm, strict=False):
        err = float(model - ref)
        mse_sum += err * err
        weight = 1.0 + 1.75 * max(0.0, 1.0 - d * 2.0)
        weighted_sum += (err * err) * weight
        weight_total += weight
    mse = mse_sum / float(count)
    weighted_mse = weighted_sum / max(1e-9, weight_total)

    ref_r80 = _radius_at_level(distances, ref_norm, level=0.8)
    model_r80 = _radius_at_level(distances, model_norm, level=0.8)
    ref_r50 = _radius_at_level(distances, ref_norm, level=0.5)
    model_r50 = _radius_at_level(distances, model_norm, level=0.5)
    r80_delta = float(model_r80 - ref_r80)
    r50_delta = float(model_r50 - ref_r50)
    score = float(weighted_mse + abs(r80_delta) * 0.10 + abs(r50_delta) * 0.05)
    return BeamProfileMatchMetrics(
        weighted_mse=float(weighted_mse),
        mse=float(mse),
        r80_delta=float(r80_delta),
        r50_delta=float(r50_delta),
        score=float(score),
    )


def _fit_shader_profile_to_reference(
    *,
    reference_distances: Sequence[float],
    reference_profile: Sequence[float],
    base_params: BeamShaderGemini2Params,
) -> tuple[BeamShaderGemini2Params, BeamProfileMatchMetrics]:
    current = _clamp_shader_params(base_params)
    best_params = current
    best_metrics = _profile_match_metrics(
        reference_distances=reference_distances,
        reference_profile=reference_profile,
        params=current,
    )

    a_values = tuple(0.5 + 0.1 * float(i) for i in range(16))
    b_values = tuple(-10.0 + 0.5 * float(i) for i in range(20))
    c_values = tuple(-0.05 + 0.01 * float(i) for i in range(16))

    for a in a_values:
        for b in b_values:
            for c in c_values:
                candidate = BeamShaderGemini2Params(
                    approx_a=float(a),
                    approx_b=float(b),
                    approx_c=float(c),
                    intensity_gain=float(current.intensity_gain),
                )
                metrics = _profile_match_metrics(
                    reference_distances=reference_distances,
                    reference_profile=reference_profile,
                    params=candidate,
                )
                if metrics.score < best_metrics.score:
                    best_params = candidate
                    best_metrics = metrics
    return best_params, best_metrics


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    q = clamp(float(q), 0.0, 1.0)
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    rank = q * float(len(ordered) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return ordered[lo]
    frac = rank - float(lo)
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return float(sum(float(v) for v in values) / float(len(values)))


def _get_beam_gemini_2_shader() -> rl.Shader | None:
    global _BEAM_GEMINI_2_SHADER_TRIED, _BEAM_GEMINI_2_SHADER
    global _BEAM_GEMINI_2_APPROX_A_LOC, _BEAM_GEMINI_2_APPROX_B_LOC
    global _BEAM_GEMINI_2_APPROX_C_LOC, _BEAM_GEMINI_2_INTENSITY_GAIN_LOC, _BEAM_GEMINI_2_COLOR_LOC
    global _BEAM_GEMINI_2_STEP_UV_LOC, _BEAM_GEMINI_2_COVER_LEN_LOC
    global _BEAM_GEMINI_2_HALO_W_LOC, _BEAM_GEMINI_2_CAP_SCALE_LOC
    if _BEAM_GEMINI_2_SHADER_TRIED:
        if _BEAM_GEMINI_2_SHADER is not None and int(_BEAM_GEMINI_2_SHADER.id) > 0:
            return _BEAM_GEMINI_2_SHADER
        return None

    _BEAM_GEMINI_2_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_GEMINI_2_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_GEMINI_2_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_GEMINI_2_SHADER = None
        return None

    _BEAM_GEMINI_2_SHADER = shader
    _BEAM_GEMINI_2_APPROX_A_LOC = int(rl.get_shader_location(shader, "u_approx_a"))
    _BEAM_GEMINI_2_APPROX_B_LOC = int(rl.get_shader_location(shader, "u_approx_b"))
    _BEAM_GEMINI_2_APPROX_C_LOC = int(rl.get_shader_location(shader, "u_approx_c"))
    _BEAM_GEMINI_2_INTENSITY_GAIN_LOC = int(rl.get_shader_location(shader, "u_intensity_gain"))
    _BEAM_GEMINI_2_STEP_UV_LOC = int(rl.get_shader_location(shader, "u_step_uv"))
    _BEAM_GEMINI_2_COVER_LEN_LOC = int(rl.get_shader_location(shader, "u_cover_len"))
    _BEAM_GEMINI_2_HALO_W_LOC = int(rl.get_shader_location(shader, "u_halo_w"))
    _BEAM_GEMINI_2_CAP_SCALE_LOC = int(rl.get_shader_location(shader, "u_cap_scale"))
    _BEAM_GEMINI_2_COLOR_LOC = int(rl.get_shader_location(shader, "colDiffuse"))
    return _BEAM_GEMINI_2_SHADER


def _get_beam_stamped_analytic_shader() -> rl.Shader | None:
    global _BEAM_STAMPED_ANALYTIC_SHADER_TRIED, _BEAM_STAMPED_ANALYTIC_SHADER, _BEAM_STAMPED_ANALYTIC_COLOR_LOC
    if _BEAM_STAMPED_ANALYTIC_SHADER_TRIED:
        if _BEAM_STAMPED_ANALYTIC_SHADER is not None and int(_BEAM_STAMPED_ANALYTIC_SHADER.id) > 0:
            return _BEAM_STAMPED_ANALYTIC_SHADER
        return None

    _BEAM_STAMPED_ANALYTIC_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_STAMPED_ANALYTIC_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_STAMPED_ANALYTIC_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_STAMPED_ANALYTIC_SHADER = None
        return None

    _BEAM_STAMPED_ANALYTIC_SHADER = shader
    _BEAM_STAMPED_ANALYTIC_COLOR_LOC = int(rl.get_shader_location(shader, "colDiffuse"))
    return _BEAM_STAMPED_ANALYTIC_SHADER


def _get_beam_stamped_virtual_shader() -> rl.Shader | None:
    global _BEAM_STAMPED_VIRTUAL_SHADER_TRIED, _BEAM_STAMPED_VIRTUAL_SHADER
    global _BEAM_STAMPED_VIRTUAL_COLOR_LOC, _BEAM_STAMPED_VIRTUAL_STEP_UV_LOC
    global _BEAM_STAMPED_VIRTUAL_STAMP_SCALE_LOC, _BEAM_STAMPED_VIRTUAL_STAMP_DECAY_LOC
    global _BEAM_STAMPED_VIRTUAL_STAMP_QUAD_LOC, _BEAM_STAMPED_VIRTUAL_STAMP_OFFSET_LOC
    global _BEAM_STAMPED_VIRTUAL_INTENSITY_GAIN_LOC
    global _BEAM_STAMPED_VIRTUAL_CORE_FLAT_STEP_FRACTION_LOC, _BEAM_STAMPED_VIRTUAL_CORE_SUPPORT_WEIGHT_LOC
    if _BEAM_STAMPED_VIRTUAL_SHADER_TRIED:
        if _BEAM_STAMPED_VIRTUAL_SHADER is not None and int(_BEAM_STAMPED_VIRTUAL_SHADER.id) > 0:
            return _BEAM_STAMPED_VIRTUAL_SHADER
        return None

    _BEAM_STAMPED_VIRTUAL_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_STAMPED_VIRTUAL_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_STAMPED_VIRTUAL_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_STAMPED_VIRTUAL_SHADER = None
        return None

    _BEAM_STAMPED_VIRTUAL_SHADER = shader
    _BEAM_STAMPED_VIRTUAL_COLOR_LOC = int(rl.get_shader_location(shader, "colDiffuse"))
    _BEAM_STAMPED_VIRTUAL_STEP_UV_LOC = int(rl.get_shader_location(shader, "u_step_uv"))
    _BEAM_STAMPED_VIRTUAL_STAMP_SCALE_LOC = int(rl.get_shader_location(shader, "u_stamp_scale"))
    _BEAM_STAMPED_VIRTUAL_STAMP_DECAY_LOC = int(rl.get_shader_location(shader, "u_stamp_decay"))
    _BEAM_STAMPED_VIRTUAL_STAMP_QUAD_LOC = int(rl.get_shader_location(shader, "u_stamp_quad"))
    _BEAM_STAMPED_VIRTUAL_STAMP_OFFSET_LOC = int(rl.get_shader_location(shader, "u_stamp_offset"))
    _BEAM_STAMPED_VIRTUAL_INTENSITY_GAIN_LOC = int(rl.get_shader_location(shader, "u_intensity_gain"))
    _BEAM_STAMPED_VIRTUAL_CORE_FLAT_STEP_FRACTION_LOC = int(
        rl.get_shader_location(shader, "u_core_flat_step_fraction"),
    )
    _BEAM_STAMPED_VIRTUAL_CORE_SUPPORT_WEIGHT_LOC = int(rl.get_shader_location(shader, "u_core_support_weight"))
    return _BEAM_STAMPED_VIRTUAL_SHADER


def _get_beam_ext_claude_shader() -> rl.Shader | None:
    global _BEAM_EXT_CLAUDE_SHADER_TRIED, _BEAM_EXT_CLAUDE_SHADER
    global _BEAM_EXT_CLAUDE_COLOR_LOC, _BEAM_EXT_CLAUDE_APPROX_A_LOC
    global _BEAM_EXT_CLAUDE_APPROX_B_LOC, _BEAM_EXT_CLAUDE_APPROX_C_LOC
    global _BEAM_EXT_CLAUDE_INTENSITY_GAIN_LOC, _BEAM_EXT_CLAUDE_LONGITUDINAL_GAMMA_LOC
    global _BEAM_EXT_CLAUDE_RADIUS_TAPER_LOC, _BEAM_EXT_CLAUDE_CORE_WEIGHT_LOC
    global _BEAM_EXT_CLAUDE_HALO_DECAY_LOC, _BEAM_EXT_CLAUDE_CAP_SOFTNESS_LOC
    if _BEAM_EXT_CLAUDE_SHADER_TRIED:
        if _BEAM_EXT_CLAUDE_SHADER is not None and int(_BEAM_EXT_CLAUDE_SHADER.id) > 0:
            return _BEAM_EXT_CLAUDE_SHADER
        return None

    _BEAM_EXT_CLAUDE_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_EXT_CLAUDE_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_EXT_CLAUDE_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_EXT_CLAUDE_SHADER = None
        return None

    _BEAM_EXT_CLAUDE_SHADER = shader
    _BEAM_EXT_CLAUDE_COLOR_LOC = int(rl.get_shader_location(shader, "colDiffuse"))
    _BEAM_EXT_CLAUDE_APPROX_A_LOC = int(rl.get_shader_location(shader, "u_approx_a"))
    _BEAM_EXT_CLAUDE_APPROX_B_LOC = int(rl.get_shader_location(shader, "u_approx_b"))
    _BEAM_EXT_CLAUDE_APPROX_C_LOC = int(rl.get_shader_location(shader, "u_approx_c"))
    _BEAM_EXT_CLAUDE_INTENSITY_GAIN_LOC = int(rl.get_shader_location(shader, "u_intensity_gain"))
    _BEAM_EXT_CLAUDE_LONGITUDINAL_GAMMA_LOC = int(rl.get_shader_location(shader, "u_longitudinal_gamma"))
    _BEAM_EXT_CLAUDE_RADIUS_TAPER_LOC = int(rl.get_shader_location(shader, "u_radius_taper"))
    _BEAM_EXT_CLAUDE_CORE_WEIGHT_LOC = int(rl.get_shader_location(shader, "u_core_weight"))
    _BEAM_EXT_CLAUDE_HALO_DECAY_LOC = int(rl.get_shader_location(shader, "u_halo_decay"))
    _BEAM_EXT_CLAUDE_CAP_SOFTNESS_LOC = int(rl.get_shader_location(shader, "u_cap_softness"))
    return _BEAM_EXT_CLAUDE_SHADER


def _get_beam_ext_gemini_shader() -> rl.Shader | None:
    global _BEAM_EXT_GEMINI_SHADER_TRIED, _BEAM_EXT_GEMINI_SHADER
    global _BEAM_EXT_GEMINI_COLOR_LOC, _BEAM_EXT_GEMINI_HALO_A_LOC
    global _BEAM_EXT_GEMINI_HALO_B_LOC, _BEAM_EXT_GEMINI_CORE_A_LOC
    global _BEAM_EXT_GEMINI_CORE_B_LOC, _BEAM_EXT_GEMINI_APPROX_C_LOC
    global _BEAM_EXT_GEMINI_INTENSITY_GAIN_LOC, _BEAM_EXT_GEMINI_TAIL_WIDTH_LOC
    global _BEAM_EXT_GEMINI_CAP_SCALE_LOC
    if _BEAM_EXT_GEMINI_SHADER_TRIED:
        if _BEAM_EXT_GEMINI_SHADER is not None and int(_BEAM_EXT_GEMINI_SHADER.id) > 0:
            return _BEAM_EXT_GEMINI_SHADER
        return None

    _BEAM_EXT_GEMINI_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_EXT_GEMINI_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_EXT_GEMINI_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_EXT_GEMINI_SHADER = None
        return None

    _BEAM_EXT_GEMINI_SHADER = shader
    _BEAM_EXT_GEMINI_COLOR_LOC = int(rl.get_shader_location(shader, "colDiffuse"))
    _BEAM_EXT_GEMINI_HALO_A_LOC = int(rl.get_shader_location(shader, "u_halo_a"))
    _BEAM_EXT_GEMINI_HALO_B_LOC = int(rl.get_shader_location(shader, "u_halo_b"))
    _BEAM_EXT_GEMINI_CORE_A_LOC = int(rl.get_shader_location(shader, "u_core_a"))
    _BEAM_EXT_GEMINI_CORE_B_LOC = int(rl.get_shader_location(shader, "u_core_b"))
    _BEAM_EXT_GEMINI_APPROX_C_LOC = int(rl.get_shader_location(shader, "u_approx_c"))
    _BEAM_EXT_GEMINI_INTENSITY_GAIN_LOC = int(rl.get_shader_location(shader, "u_intensity_gain"))
    _BEAM_EXT_GEMINI_TAIL_WIDTH_LOC = int(rl.get_shader_location(shader, "u_tail_width"))
    _BEAM_EXT_GEMINI_CAP_SCALE_LOC = int(rl.get_shader_location(shader, "u_cap_scale"))
    return _BEAM_EXT_GEMINI_SHADER


def _get_beam_ext_gpt_pro_shader() -> rl.Shader | None:
    global _BEAM_EXT_GPT_PRO_SHADER_TRIED, _BEAM_EXT_GPT_PRO_SHADER
    global _BEAM_EXT_GPT_PRO_COLOR_LOC, _BEAM_EXT_GPT_PRO_APPROX_A_LOC
    global _BEAM_EXT_GPT_PRO_APPROX_B_LOC, _BEAM_EXT_GPT_PRO_APPROX_C_LOC
    global _BEAM_EXT_GPT_PRO_INTENSITY_GAIN_LOC, _BEAM_EXT_GPT_PRO_STEP_UV_LOC
    global _BEAM_EXT_GPT_PRO_COVER_LEN_LOC, _BEAM_EXT_GPT_PRO_HALO_W_LOC
    if _BEAM_EXT_GPT_PRO_SHADER_TRIED:
        if _BEAM_EXT_GPT_PRO_SHADER is not None and int(_BEAM_EXT_GPT_PRO_SHADER.id) > 0:
            return _BEAM_EXT_GPT_PRO_SHADER
        return None

    _BEAM_EXT_GPT_PRO_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_BEAM_SHADER_VS_330, _BEAM_EXT_GPT_PRO_FS_330)
    except (RuntimeError, OSError, ValueError):
        _BEAM_EXT_GPT_PRO_SHADER = None
        return None

    if int(shader.id) <= 0:
        _BEAM_EXT_GPT_PRO_SHADER = None
        return None

    _BEAM_EXT_GPT_PRO_SHADER = shader
    _BEAM_EXT_GPT_PRO_COLOR_LOC = int(rl.get_shader_location(shader, "colDiffuse"))
    _BEAM_EXT_GPT_PRO_APPROX_A_LOC = int(rl.get_shader_location(shader, "u_approx_a"))
    _BEAM_EXT_GPT_PRO_APPROX_B_LOC = int(rl.get_shader_location(shader, "u_approx_b"))
    _BEAM_EXT_GPT_PRO_APPROX_C_LOC = int(rl.get_shader_location(shader, "u_approx_c"))
    _BEAM_EXT_GPT_PRO_INTENSITY_GAIN_LOC = int(rl.get_shader_location(shader, "u_intensity_gain"))
    _BEAM_EXT_GPT_PRO_STEP_UV_LOC = int(rl.get_shader_location(shader, "u_step_uv"))
    _BEAM_EXT_GPT_PRO_COVER_LEN_LOC = int(rl.get_shader_location(shader, "u_cover_len"))
    _BEAM_EXT_GPT_PRO_HALO_W_LOC = int(rl.get_shader_location(shader, "u_halo_w"))
    return _BEAM_EXT_GPT_PRO_SHADER


def _mode_label(mode: BeamRenderMode) -> str:
    if mode == BeamRenderMode.BASELINE_SPRITE:
        return "baseline"
    if mode == BeamRenderMode.SHADER_STAMPED_VIRTUAL:
        return "shader-stamped-virtual"
    if mode == BeamRenderMode.SHADER_EXT_CLAUDE:
        return "shader-ext-claude"
    if mode == BeamRenderMode.SHADER_EXT_GEMINI:
        return "shader-ext-gemini"
    if mode == BeamRenderMode.SHADER_EXT_GPT_PRO:
        return "shader-ext-gpt-pro"
    return "shader-gemini-2"


def _preset_label(preset: BeamScenarioPreset) -> str:
    if preset == BeamScenarioPreset.PLASMA_LIKE:
        return "plasma-like"
    if preset == BeamScenarioPreset.CROWD_STRESS:
        return "crowd-stress"
    return "long-uncapped"


def _beam_debug_asset_candidates(preferred_root: Path) -> tuple[Path, ...]:
    candidates = (
        Path(preferred_root),
        default_runtime_dir(),
        Path("artifacts") / "assets",
    )
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.expanduser().resolve(strict=False)
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
    return tuple(unique)


def _has_beam_assets(assets_root: Path) -> bool:
    if find_paq_path(assets_root) is not None:
        return True
    projs = resolve_asset_path(assets_root, "game/projs.jaz")
    particles = resolve_asset_path(assets_root, "game/particles.jaz")
    return projs is not None and particles is not None


def resolve_beam_debug_assets_root(preferred_root: Path) -> Path:
    for candidate in _beam_debug_asset_candidates(preferred_root):
        if _has_beam_assets(candidate):
            return candidate
    return Path(preferred_root).expanduser().resolve(strict=False)


def _base_alpha_for_life(life: float) -> float:
    life = float(life)
    if life >= 0.4:
        return 1.0
    return float(clamp(life * 2.5, 0.0, 1.0))


def _visible_offsets_for_mode(
    *,
    mode: BeamRenderMode,
    plan: BeamSamplePlan,
    base_alpha: float,
    screen_length_px: float,
) -> tuple[float, ...]:
    del mode, screen_length_px
    if base_alpha <= 1e-3:
        return ()
    candidate_offsets = tuple(float(s) for s in iter_beam_sample_offsets(plan))

    span = float(plan.span)
    start = float(plan.start)
    visible: list[float] = []
    for offset in candidate_offsets:
        t = (float(offset) - start) / span if span > 1e-6 else 1.0
        seg_alpha = float(t) * float(base_alpha)
        if seg_alpha <= 1e-3:
            continue
        visible.append(float(offset))
    return tuple(visible)


def _head_region_segment_count(offsets: Sequence[float], *, plan: BeamSamplePlan) -> int:
    if not offsets:
        return 0
    span = float(plan.span)
    start = float(plan.start)
    count = 0
    for offset in offsets:
        t = (float(offset) - start) / span if span > 1e-6 else 1.0
        if t >= HEAD_REGION_T_MIN:
            count += 1
    return int(count)


def estimate_beam_frame_counts(
    inputs: Sequence[BeamCountInput],
    *,
    mode: BeamRenderMode,
    is_fire: bool,
    draw_heads_enabled: bool = True,
) -> BeamDrawCounts:
    body_calls = 0
    head_calls = 0
    overlay_calls = 0
    visible_segments = 0
    head_region_segments = 0
    shader_beam_calls = 0

    for item in inputs:
        plan = item.plan
        if plan is None:
            continue

        base_alpha = _base_alpha_for_life(item.life)
        if base_alpha <= 1e-3:
            continue

        offsets = _visible_offsets_for_mode(
            mode=mode,
            plan=plan,
            base_alpha=base_alpha,
            screen_length_px=float(item.screen_length_px),
        )
        segment_count = len(offsets)
        visible_segments += int(segment_count)
        head_region_segments += _head_region_segment_count(offsets, plan=plan)

        if mode == BeamRenderMode.BASELINE_SPRITE:
            if bool(draw_heads_enabled):
                head_calls += 1
                if bool(is_fire) and float(item.life) >= 0.4:
                    overlay_calls += 1
            body_calls += int(segment_count)
        elif segment_count >= 1:
            shader_beam_calls += 1
            if bool(draw_heads_enabled):
                head_calls += 1

    if mode != BeamRenderMode.BASELINE_SPRITE:
        body_calls = int(shader_beam_calls)
        overlay_calls = 0

    return BeamDrawCounts(
        body_calls=int(body_calls),
        head_calls=int(head_calls),
        overlay_calls=int(overlay_calls),
        visible_segments=int(visible_segments),
        head_region_segments=int(head_region_segments),
    )


@dataclass(frozen=True, slots=True)
class _PreviewProjectile:
    index: int
    origin_screen: Vec2
    head_screen: Vec2
    dist_units: float
    life: float
    plan: BeamSamplePlan | None


@dataclass(frozen=True, slots=True)
class _RenderPrep:
    preview: _PreviewProjectile
    plan: BeamSamplePlan
    ray: Vec2
    dist_units: float
    rotation_rad: float
    base_alpha: float
    offsets: tuple[float, ...]


class BeamDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._requested_assets_root = Path(ctx.assets_dir).expanduser().resolve(strict=False)
        self._assets_root = resolve_beam_debug_assets_root(self._requested_assets_root)
        self._small: SmallFontData | None = None
        self._texture_loader: TextureLoader | None = None
        self._projs_texture: rl.Texture | None = None
        self._particles_texture: rl.Texture | None = None
        self._fire_glow_src: rl.Rectangle | None = None
        self._missing_assets: set[str] = set()

        self.close_requested = False
        self._screenshot_requested = False

        self._paused = True
        self._phase = 0.0
        self._sim_speed = 1.0

        self._projectile_count = 14
        self._selected_projectile_index = 0
        self._base_distance_units = 220.0
        self._distance_jitter_units = 80.0
        self._distance_to_screen_scale = 1.0

        self._cap_enabled = True
        self._head_render_enabled = True
        self._head_cap_variant = HeadCapVariant.BODY_CAP
        self._show_all_segment_markers = False
        self._show_geometry_overlay = False
        self._force_life_high = True

        self._use_fire_profile = True
        self._ion_preset_index = 0
        self._sync_effect_scale()

        self._render_mode = BeamRenderMode.BASELINE_SPRITE
        self._side_by_side_enabled = False
        self._scenario_preset = BeamScenarioPreset.PLASMA_LIKE
        self._rolling_by_mode_preset: dict[tuple[BeamRenderMode, BeamScenarioPreset], BeamModeRollingStats] = {}
        self._last_frame_stats: BeamFrameStats | None = None
        self._last_render_result: BeamRenderFrameResult | None = None
        self._last_shader_fallback = False

        self._bench_active = False
        self._bench_frames_per_mode = BENCH_FRAMES_PER_MODE
        self._bench_frame_cursor = 0
        self._bench_total_frames = 0
        self._bench_completed = False

        self._batch_probe_auto = False
        self._batch_probe_run_once = False
        self._batch_probe_quads = BATCH_PROBE_QUADS_DEFAULT
        self._batch_probe_last: BatchProbeResult | None = None

        self._shader_gemini_2_params = BeamShaderGemini2Params()
        self._shader_ext_claude_params = BeamShaderExtClaudeParams()
        self._shader_ext_gemini_params = BeamShaderExtGeminiParams()
        self._shader_ext_gpt_pro_params = BeamShaderExtGptProParams()
        self._shader_reference_profile: BeamSpriteReferenceProfile | None = None
        self._shader_profile_metrics: BeamProfileMatchMetrics | None = None
        self._shader_fit_status = "pending"
        self._shader_fit_elapsed_ms = 0.0
        self._shader_fit_requested = False

        self.apply_scenario_preset(BeamScenarioPreset.PLASMA_LIKE)

    @property
    def render_mode(self) -> BeamRenderMode:
        return self._render_mode

    @property
    def scenario_preset(self) -> BeamScenarioPreset:
        return self._scenario_preset

    def apply_scenario_preset(self, preset: BeamScenarioPreset) -> None:
        config = beam_scenario_config(preset)
        self._scenario_preset = preset
        self._projectile_count = int(config.projectile_count)
        self._base_distance_units = float(config.base_distance_units)
        self._distance_jitter_units = float(config.distance_jitter_units)
        self._cap_enabled = bool(config.cap_enabled)
        self._use_fire_profile = bool(config.use_fire_profile)
        self._force_life_high = bool(config.force_life_high)
        self._distance_to_screen_scale = float(config.distance_to_screen_scale)
        self._sync_effect_scale()

    def cycle_render_mode(self) -> None:
        self._render_mode = cycle_beam_render_mode(self._render_mode)

    def toggle_side_by_side(self) -> None:
        self._side_by_side_enabled = not bool(self._side_by_side_enabled)

    def reset_experiment_stats(self) -> None:
        self._rolling_by_mode_preset.clear()
        self._last_frame_stats = None
        self._last_render_result = None
        self._bench_completed = False

    def start_benchmark(self) -> None:
        self.reset_experiment_stats()
        self._bench_active = True
        self._bench_completed = False
        self._bench_frame_cursor = 0
        frames_per_mode = max(1, int(self._bench_frames_per_mode))
        self._bench_frames_per_mode = frames_per_mode
        self._bench_total_frames = int(frames_per_mode * len(_RENDER_MODE_ORDER))
        self._render_mode = _RENDER_MODE_ORDER[0]
        self._side_by_side_enabled = False

    def stop_benchmark(self) -> None:
        self._bench_active = False
        self._bench_completed = False

    def _benchmark_mode_index(self) -> int:
        frames_per_mode = max(1, int(self._bench_frames_per_mode))
        index = int(self._bench_frame_cursor // frames_per_mode)
        return max(0, min(len(_RENDER_MODE_ORDER) - 1, index))

    def _benchmark_progress_label(self) -> str:
        if not self._bench_active:
            if self._bench_completed:
                return "completed"
            return "off"
        idx = self._benchmark_mode_index()
        mode = _mode_label(_RENDER_MODE_ORDER[idx])
        return f"running {self._bench_frame_cursor + 1}/{self._bench_total_frames} mode={mode}"

    def _advance_benchmark_after_frame(self) -> None:
        if not self._bench_active:
            return
        self._bench_frame_cursor += 1
        if self._bench_frame_cursor >= self._bench_total_frames:
            self._bench_active = False
            self._bench_completed = True
            self._render_mode = BeamRenderMode.BASELINE_SPRITE
            return
        self._render_mode = _RENDER_MODE_ORDER[self._benchmark_mode_index()]

    def _active_projectile_type_id(self) -> int:
        if self._use_fire_profile:
            return int(ProjectileTypeId.FIRE_BULLETS)
        return int(self._active_ion_preset().projectile_type_id)

    def _active_ion_preset(self) -> BeamIonPreset:
        idx = int(self._ion_preset_index) % len(_ION_PRESET_ORDER)
        return _ION_PRESET_ORDER[idx]

    def cycle_ion_preset(self) -> None:
        idx = int(self._ion_preset_index) + 1
        self._ion_preset_index = int(idx % len(_ION_PRESET_ORDER))
        self._sync_effect_scale()

    @staticmethod
    def _projectile_speed_units_per_second_for_type(type_id: int) -> float:
        entry = weapon_entry_for_projectile_type_id(int(type_id))
        meta = int(entry.projectile_meta) if entry is not None and entry.projectile_meta is not None else 45
        steps = max(1, int(meta))
        return float(steps) * float(PROJECTILE_SPEED_UNITS_PER_META)

    def _projectile_speed_units_per_second(self) -> float:
        return self._projectile_speed_units_per_second_for_type(self._active_projectile_type_id())

    def _distance_scale_from_base(self) -> float:
        return max(0.01, float(self._base_distance_units) / float(DISTANCE_SCALE_REFERENCE_UNITS))

    def _sync_effect_scale(self) -> None:
        type_id = self._active_projectile_type_id()
        self._effect_scale = float(beam_effect_scale(type_id))

    @staticmethod
    def _gemini_2_body_shape_params_for_type(type_id: int) -> tuple[float, float, float]:
        if int(type_id) == int(ProjectileTypeId.ION_CANNON):
            return (
                float(SHADER_GEMINI_2_COVER_LEN_ION_CANNON),
                float(SHADER_GEMINI_2_HALO_W_ION_CANNON),
                float(SHADER_GEMINI_2_CAP_SCALE_DEFAULT),
            )
        if int(type_id) == int(ProjectileTypeId.ION_RIFLE):
            return (
                float(SHADER_GEMINI_2_COVER_LEN_DEFAULT),
                float(SHADER_GEMINI_2_HALO_W_ION_RIFLE),
                float(SHADER_GEMINI_2_CAP_SCALE_DEFAULT),
            )
        if int(type_id) == int(ProjectileTypeId.ION_MINIGUN):
            return (
                float(SHADER_GEMINI_2_COVER_LEN_DEFAULT),
                float(SHADER_GEMINI_2_HALO_W_DEFAULT),
                float(SHADER_GEMINI_2_CAP_SCALE_DEFAULT),
            )
        return (
            float(SHADER_GEMINI_2_COVER_LEN_DEFAULT),
            float(SHADER_GEMINI_2_HALO_W_DEFAULT),
            float(SHADER_GEMINI_2_CAP_SCALE_DEFAULT),
        )

    def _gemini_2_body_shape_params(self) -> tuple[float, float, float]:
        return self._gemini_2_body_shape_params_for_type(self._active_projectile_type_id())

    def _iter_asset_roots_for_open(self) -> tuple[Path, ...]:
        roots = _beam_debug_asset_candidates(self._requested_assets_root)
        primary = resolve_beam_debug_assets_root(self._requested_assets_root)
        ordered: list[Path] = [primary]
        ordered.extend(root for root in roots if root != primary)
        return tuple(ordered)

    def _load_optional_texture(self, *, name: str, cache_path: str) -> rl.Texture | None:
        if self._texture_loader is None:
            return None
        try:
            return self._texture_loader.get(name=name, paq_rel=cache_path)
        except FileNotFoundError:
            self._missing_assets.add(cache_path)
            return None

    @staticmethod
    def _compute_fire_glow_src(texture: rl.Texture | None) -> rl.Rectangle | None:
        if texture is None:
            return None
        atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
        if atlas is None:
            return None
        grid = SIZE_CODE_GRID.get(int(atlas.size_code))
        if grid is None:
            return None
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        frame = int(atlas.frame)
        col = frame % grid
        row = frame // grid
        return rl.Rectangle(
            cell_w * float(col),
            cell_h * float(row),
            max(0.0, cell_w - 2.0),
            max(0.0, cell_h - 2.0),
        )

    @staticmethod
    def _sample_bilinear_alpha(alpha_rows: Sequence[Sequence[float]], *, x: float, y: float) -> float:
        height = len(alpha_rows)
        if height <= 0:
            return 0.0
        width = len(alpha_rows[0])
        if width <= 0:
            return 0.0

        x0 = int(math.floor(float(x)))
        y0 = int(math.floor(float(y)))
        x1 = x0 + 1
        y1 = y0 + 1
        fx = float(x) - float(x0)
        fy = float(y) - float(y0)

        def pick(px: int, py: int) -> float:
            if px < 0 or py < 0 or px >= width or py >= height:
                return 0.0
            return float(alpha_rows[py][px])

        c00 = pick(x0, y0)
        c10 = pick(x1, y0)
        c01 = pick(x0, y1)
        c11 = pick(x1, y1)
        tx0 = c00 * (1.0 - fx) + c10 * fx
        tx1 = c01 * (1.0 - fx) + c11 * fx
        return float(tx0 * (1.0 - fy) + tx1 * fy)

    def _analyze_sprite_reference_profile(self, texture: rl.Texture) -> BeamSpriteReferenceProfile | None:
        image = rl.load_image_from_texture(texture)
        try:
            image_width = max(1, int(image.width))
            image_height = max(1, int(image.height))
            grid = 4
            frame = 2
            cell_w = max(1, image_width // grid)
            cell_h = max(1, image_height // grid)
            col = frame % grid
            row = frame // grid
            x0 = int(col * cell_w)
            y0 = int(row * cell_h)

            alpha_rows: list[list[float]] = []
            total = 0.0
            weighted_x = 0.0
            weighted_y = 0.0
            for py in range(cell_h):
                row_values: list[float] = []
                for px in range(cell_w):
                    src_x = min(image_width - 1, x0 + px)
                    src_y = min(image_height - 1, y0 + py)
                    a = float(rl.get_image_color(image, src_x, src_y).a) / 255.0
                    row_values.append(a)
                    total += a
                    weighted_x += float(px) * a
                    weighted_y += float(py) * a
                alpha_rows.append(row_values)

            if total <= 1e-9:
                return None

            centroid_x = weighted_x / total
            centroid_y = weighted_y / total
            radius_px = max(1.0, 0.5 * min(float(cell_w), float(cell_h)))

            distances: list[float] = []
            profile: list[float] = []
            ring_samples = max(8, int(SHADER_GEMINI_2_PROFILE_RING_SAMPLES))
            sample_count = max(8, int(SHADER_GEMINI_2_PROFILE_SAMPLE_COUNT))
            for i in range(sample_count):
                d_norm = float(i) / float(sample_count - 1)
                radius = d_norm * radius_px
                acc = 0.0
                for j in range(ring_samples):
                    theta = (float(j) / float(ring_samples)) * math.tau
                    sx = centroid_x + math.cos(theta) * radius
                    sy = centroid_y + math.sin(theta) * radius
                    acc += self._sample_bilinear_alpha(alpha_rows, x=sx, y=sy)
                distances.append(d_norm)
                profile.append(acc / float(ring_samples))

            return BeamSpriteReferenceProfile(
                distances_norm=tuple(distances),
                alpha_profile=tuple(profile),
                radius_px=float(radius_px),
                centroid_x=float(centroid_x),
                centroid_y=float(centroid_y),
                source="projs frame2 alpha + bilinear ring sampling",
            )
        finally:
            rl.unload_image(image)

    def _refresh_shader_reference_profile(self) -> None:
        texture = self._projs_texture
        if texture is None:
            self._shader_reference_profile = None
            self._shader_profile_metrics = None
            self._shader_fit_status = "ref unavailable: missing projs texture"
            return
        reference = self._analyze_sprite_reference_profile(texture)
        if reference is None:
            self._shader_reference_profile = None
            self._shader_profile_metrics = None
            self._shader_fit_status = "ref unavailable: empty alpha profile"
            return
        self._shader_reference_profile = reference
        self._update_shader_profile_metrics()
        self._shader_fit_status = "ref ready"

    def _update_shader_profile_metrics(self) -> None:
        reference = self._shader_reference_profile
        if reference is None:
            self._shader_profile_metrics = None
            return
        self._shader_profile_metrics = _profile_match_metrics(
            reference_distances=reference.distances_norm,
            reference_profile=reference.alpha_profile,
            params=self._shader_gemini_2_params,
        )

    def _apply_shader_param_delta(
        self,
        *,
        approx_a: float = 0.0,
        approx_b: float = 0.0,
        approx_c: float = 0.0,
        intensity_gain: float = 0.0,
    ) -> None:
        params = self._shader_gemini_2_params
        self._shader_gemini_2_params = _clamp_shader_params(
            BeamShaderGemini2Params(
                approx_a=float(params.approx_a + approx_a),
                approx_b=float(params.approx_b + approx_b),
                approx_c=float(params.approx_c + approx_c),
                intensity_gain=float(params.intensity_gain + intensity_gain),
            ),
        )
        self._update_shader_profile_metrics()
        self._shader_fit_status = "manual tune"

    def _reset_shader_params(self) -> None:
        self._shader_gemini_2_params = _clamp_shader_params(BeamShaderGemini2Params())
        self._update_shader_profile_metrics()
        self._shader_fit_status = "params reset"

    def _toggle_research_params(self) -> None:
        a_r, b_r, c_r, g_r = SHADER_GEMINI_2_RESEARCH_PARAMS
        current = self._shader_gemini_2_params
        research = BeamShaderGemini2Params(approx_a=a_r, approx_b=b_r, approx_c=c_r, intensity_gain=g_r)
        is_research = (
            abs(current.approx_a - a_r) < 1e-4
            and abs(current.approx_b - b_r) < 1e-4
            and abs(current.approx_c - c_r) < 1e-4
        )
        if is_research:
            self._shader_gemini_2_params = _clamp_shader_params(BeamShaderGemini2Params())
            self._shader_fit_status = "fitted (default)"
        else:
            self._shader_gemini_2_params = _clamp_shader_params(research)
            self._shader_fit_status = "research ref"
        self._update_shader_profile_metrics()

    def _run_shader_profile_autofit(self) -> None:
        reference = self._shader_reference_profile
        if reference is None:
            self._shader_fit_status = "fit failed: no reference profile"
            self._shader_fit_elapsed_ms = 0.0
            self._shader_fit_requested = False
            return
        started = time.perf_counter()
        base = self._shader_gemini_2_params
        fitted, metrics = _fit_shader_profile_to_reference(
            reference_distances=reference.distances_norm,
            reference_profile=reference.alpha_profile,
            base_params=base,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        # Preserve user-tuned gain while fitting cross-section softness/shape.
        self._shader_gemini_2_params = _clamp_shader_params(
            BeamShaderGemini2Params(
                approx_a=float(fitted.approx_a),
                approx_b=float(fitted.approx_b),
                approx_c=float(fitted.approx_c),
                intensity_gain=float(base.intensity_gain),
            ),
        )
        self._shader_profile_metrics = metrics
        self._shader_fit_elapsed_ms = float(elapsed_ms)
        self._shader_fit_status = (
            f"autofit ok: score={metrics.score:.5f} r80_delta={metrics.r80_delta:+.4f} ({elapsed_ms:.1f} ms)"
        )
        self._shader_fit_requested = False

    def _rolling_stats(self, mode: BeamRenderMode, preset: BeamScenarioPreset) -> BeamModeRollingStats:
        key = (mode, preset)
        stats = self._rolling_by_mode_preset.get(key)
        if stats is None:
            stats = BeamModeRollingStats(window_size=ROLLING_WINDOW_SIZE)
            self._rolling_by_mode_preset[key] = stats
        return stats

    def _record_frame_stats(self, frame: BeamFrameStats) -> None:
        self._rolling_stats(self._render_mode, self._scenario_preset).add(frame)
        self._last_frame_stats = frame

    def open(self) -> None:
        self._missing_assets.clear()
        last_error: FileNotFoundError | None = None
        for assets_root in self._iter_asset_roots_for_open():
            try:
                small = load_small_font(assets_root)
            except FileNotFoundError as exc:
                last_error = exc
                continue

            self._assets_root = assets_root
            self._small = small
            self._texture_loader = TextureLoader.from_assets_root(assets_root)
            self._projs_texture = self._load_optional_texture(name="projs", cache_path="game/projs.jaz")
            self._particles_texture = self._load_optional_texture(name="particles", cache_path="game/particles.jaz")
            self._fire_glow_src = self._compute_fire_glow_src(self._particles_texture)
            self._refresh_shader_reference_profile()
            return

        if last_error is not None:
            raise last_error
        raise FileNotFoundError("Unable to resolve assets for beam-debug view.")

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        self._texture_loader = None
        self._projs_texture = None
        self._particles_texture = None
        self._fire_glow_src = None
        self._shader_reference_profile = None
        self._shader_profile_metrics = None
        self._shader_fit_status = "pending"
        self._missing_assets.clear()

    def consume_screenshot_request(self) -> bool:
        requested = bool(self._screenshot_requested)
        self._screenshot_requested = False
        return requested

    def _step_sim(self, dt: float) -> None:
        self._phase += max(0.0, float(dt)) * max(0.0, float(self._sim_speed))

    def _beam_dist_units(self, index: int) -> float:
        speed_units_per_second = self._projectile_speed_units_per_second()
        trail_window_seconds = float(NATIVE_BEAM_ACTIVE_LIFE_SECONDS)
        travel_units = speed_units_per_second * trail_window_seconds
        distance_scale = self._distance_scale_from_base()

        idx = float(index)
        wave_a = math.sin(float(self._phase) * 1.6 + idx * 0.37)
        wave_b = math.sin(float(self._phase) * 0.45 + idx * 0.09)
        jitter_units = (
            wave_a * float(self._distance_jitter_units)
            + wave_b * float(self._distance_jitter_units) * 0.25
        )
        dist = (travel_units + jitter_units) * distance_scale
        return max(2.0, float(dist))

    def _beam_life(self, index: int) -> float:
        if self._force_life_high:
            return 0.4
        idx = float(index)
        pulse = max(0.0, math.sin(float(self._phase) * 1.1 + idx * 0.31))
        return float(0.25 + pulse * 0.25)

    def _beam_step_units(self) -> float:
        return float(min(float(self._effect_scale) * 3.1, 9.0))

    def _build_previews(self) -> list[_PreviewProjectile]:
        count = max(1, int(self._projectile_count))
        width = float(rl.get_screen_width())
        height = float(rl.get_screen_height())
        center = Vec2(width * 0.5, height * 0.58)
        origin_radius = min(170.0, 38.0 + float(count) * 1.8)
        step_units = self._beam_step_units()

        previews: list[_PreviewProjectile] = []
        for index in range(count):
            theta = float(self._phase) * 0.3 + (float(index) / float(count)) * math.tau
            direction = Vec2.from_angle(theta)
            origin_screen = center + direction * origin_radius
            life = self._beam_life(index)
            dist_units = self._beam_dist_units(index)
            head_screen = origin_screen + direction * (dist_units * float(self._distance_to_screen_scale))
            max_span = 256.0 if self._cap_enabled else dist_units
            plan = build_beam_sample_plan(dist=dist_units, step=step_units, max_span=max_span)

            previews.append(
                _PreviewProjectile(
                    index=int(index),
                    origin_screen=origin_screen,
                    head_screen=head_screen,
                    dist_units=float(dist_units),
                    life=float(life),
                    plan=plan,
                ),
            )
        return previews

    def _selected_preview(self, previews: list[_PreviewProjectile]) -> _PreviewProjectile:
        if not previews:
            raise RuntimeError("beam preview list must not be empty")
        self._selected_projectile_index %= len(previews)
        return previews[self._selected_projectile_index]

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not bool(self._paused)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT) and self._paused:
            self._step_sim(1.0 / 60.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._projectile_count = min(200, int(self._projectile_count) + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._projectile_count = max(1, int(self._projectile_count) - 1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_COMMA):
            self._selected_projectile_index -= 1
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD):
            self._selected_projectile_index += 1

        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._base_distance_units = min(4000.0, float(self._base_distance_units) + 32.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._base_distance_units = max(8.0, float(self._base_distance_units) - 32.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
            self._distance_jitter_units = min(2500.0, float(self._distance_jitter_units) + 24.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._distance_jitter_units = max(0.0, float(self._distance_jitter_units) - 24.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_K):
            self._effect_scale = max(0.1, float(self._effect_scale) - 0.05)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_L):
            self._effect_scale = min(5.0, float(self._effect_scale) + 0.05)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_W):
            self._apply_shader_param_delta(intensity_gain=-SHADER_GEMINI_2_INTENSITY_GAIN_STEP)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_S):
            self._apply_shader_param_delta(intensity_gain=SHADER_GEMINI_2_INTENSITY_GAIN_STEP)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_MINUS):
            self._sim_speed = max(0.1, float(self._sim_speed) - 0.1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EQUAL):
            self._sim_speed = min(8.0, float(self._sim_speed) + 0.1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_F):
            self._use_fire_profile = not bool(self._use_fire_profile)
            self._sync_effect_scale()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_I):
            self.cycle_ion_preset()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_C):
            self._cap_enabled = not bool(self._cap_enabled)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_G):
            self._force_life_high = not bool(self._force_life_high)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._head_render_enabled = not bool(self._head_render_enabled)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_D):
            idx = _HEAD_CAP_VARIANT_ORDER.index(self._head_cap_variant)
            self._head_cap_variant = _HEAD_CAP_VARIANT_ORDER[(idx + 1) % len(_HEAD_CAP_VARIANT_ORDER)]
        if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
            self._show_all_segment_markers = not bool(self._show_all_segment_markers)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_V):
            self._show_geometry_overlay = not bool(self._show_geometry_overlay)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            if not self._bench_active:
                self.cycle_render_mode()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            if not self._bench_active:
                self.toggle_side_by_side()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self.apply_scenario_preset(BeamScenarioPreset.PLASMA_LIKE)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self.apply_scenario_preset(BeamScenarioPreset.CROWD_STRESS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_THREE):
            self.apply_scenario_preset(BeamScenarioPreset.LONG_UNCAPPED)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self.reset_experiment_stats()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Y):
            if self._bench_active:
                self.stop_benchmark()
            else:
                self.start_benchmark()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_X):
            self._batch_probe_run_once = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Z):
            self._batch_probe_auto = not bool(self._batch_probe_auto)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_J):
            self._batch_probe_quads = max(BATCH_PROBE_QUADS_MIN, int(self._batch_probe_quads) - BATCH_PROBE_QUADS_STEP)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_U):
            self._batch_probe_quads = min(BATCH_PROBE_QUADS_MAX, int(self._batch_probe_quads) + BATCH_PROBE_QUADS_STEP)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
            self._shader_fit_requested = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ZERO):
            self._reset_shader_params()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Q):
            self._toggle_research_params()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_B):
            self.apply_scenario_preset(BeamScenarioPreset.PLASMA_LIKE)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._phase = 0.0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True

        if self._bench_active and self._paused:
            self._paused = False

        if not self._paused:
            clamped_dt = min(max(0.0, float(dt)), 0.1)
            self._step_sim(clamped_dt)

    def _draw_grid(self) -> None:
        screen_w = rl.get_screen_width()
        screen_h = rl.get_screen_height()
        step = 64
        x = 0
        while x < screen_w:
            rl.draw_line(x, 0, x, screen_h, GRID)
            x += step
        y = 0
        while y < screen_h:
            rl.draw_line(0, y, screen_w, y, GRID)
            y += step

    @staticmethod
    def _translate_previews(previews: Sequence[_PreviewProjectile], *, dx: float, dy: float = 0.0) -> list[_PreviewProjectile]:
        if abs(float(dx)) <= 1e-6 and abs(float(dy)) <= 1e-6:
            return list(previews)
        delta = Vec2(float(dx), float(dy))
        translated: list[_PreviewProjectile] = []
        for preview in previews:
            translated.append(
                _PreviewProjectile(
                    index=int(preview.index),
                    origin_screen=preview.origin_screen + delta,
                    head_screen=preview.head_screen + delta,
                    dist_units=float(preview.dist_units),
                    life=float(preview.life),
                    plan=preview.plan,
                ),
            )
        return translated

    @staticmethod
    def _draw_compare_divider() -> None:
        mid = int(rl.get_screen_width() * 0.5)
        rl.draw_line(mid, 0, mid, rl.get_screen_height(), PANEL_DIVIDER)

    def _draw_projectile_geometry(self, preview: _PreviewProjectile, *, selected: bool) -> None:
        line_color = FIRE_LINE if self._use_fire_profile else ION_LINE
        if selected:
            line_color = SELECTED_LINE
        rl.draw_line(
            int(preview.origin_screen.x),
            int(preview.origin_screen.y),
            int(preview.head_screen.x),
            int(preview.head_screen.y),
            line_color,
        )

        rl.draw_circle(
            int(preview.origin_screen.x),
            int(preview.origin_screen.y),
            3.0 if selected else 2.0,
            ORIGIN_MARK,
        )
        rl.draw_circle(
            int(preview.head_screen.x),
            int(preview.head_screen.y),
            5.0 if selected else 3.0,
            HEAD_MARK,
        )

        plan = preview.plan
        if plan is not None and self._cap_enabled and float(plan.start) > 1e-6:
            t = float(plan.start) / max(1e-6, float(preview.dist_units))
            start_pos = preview.origin_screen + (preview.head_screen - preview.origin_screen) * t
            rl.draw_circle(
                int(start_pos.x),
                int(start_pos.y),
                3.0 if selected else 2.0,
                CAP_START_MARK,
            )

    @staticmethod
    def _draw_atlas_sprite(
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        pos: Vec2,
        scale: float,
        rotation_rad: float = 0.0,
        tint: rl.Color = rl.WHITE,
    ) -> None:
        grid = max(1, int(grid))
        frame = max(0, int(frame))
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        col = frame % grid
        row = frame // grid
        src = rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)
        w = cell_w * float(scale)
        h = cell_h * float(scale)
        dst = rl.Rectangle(pos.x, pos.y, w, h)
        origin = rl.Vector2(w * 0.5, h * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, float(rotation_rad * RAD_TO_DEG), tint)

    def _draw_fire_overlay(self, preview: _PreviewProjectile, *, alpha: float, rotation_rad: float) -> bool:
        particles_texture = self._particles_texture
        glow_src = self._fire_glow_src
        if particles_texture is None or glow_src is None:
            return False
        size = 64.0
        dst = rl.Rectangle(preview.head_screen.x, preview.head_screen.y, size, size)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        tint = RGBA(1.0, 1.0, 1.0, alpha).to_rl()
        rl.draw_texture_pro(particles_texture, glow_src, dst, origin, rotation_rad * RAD_TO_DEG, tint)
        return True

    def _build_render_preps(self, previews: Sequence[_PreviewProjectile], *, mode: BeamRenderMode) -> list[_RenderPrep]:
        preps: list[_RenderPrep] = []
        for preview in previews:
            plan = preview.plan
            if plan is None:
                continue

            ray = preview.head_screen - preview.origin_screen
            dist_units = max(1e-6, float(preview.dist_units))
            screen_length = ray.length()
            base_alpha = _base_alpha_for_life(preview.life)
            if base_alpha <= 1e-3:
                continue

            offsets = _visible_offsets_for_mode(
                mode=mode,
                plan=plan,
                base_alpha=base_alpha,
                screen_length_px=screen_length,
            )
            preps.append(
                _RenderPrep(
                    preview=preview,
                    plan=plan,
                    ray=ray,
                    dist_units=float(dist_units),
                    rotation_rad=float(ray.to_angle()),
                    base_alpha=float(base_alpha),
                    offsets=offsets,
                ),
            )
        return preps

    @staticmethod
    def _segment_t(*, offset: float, plan: BeamSamplePlan) -> float:
        span = float(plan.span)
        start = float(plan.start)
        t = (float(offset) - start) / span if span > 1e-6 else 1.0
        return float(clamp(t, 0.0, 1.0))

    @staticmethod
    def _segment_alpha(*, offset: float, plan: BeamSamplePlan, base_alpha: float) -> float:
        return float(BeamDebugView._segment_t(offset=float(offset), plan=plan)) * float(base_alpha)

    @staticmethod
    def _u8(alpha: float) -> int:
        return int(clamp(float(alpha) * 255.0, 0.0, 255.0) + 0.5)

    @staticmethod
    def _set_shader_float(shader: rl.Shader, location: int, value: float) -> None:
        if int(location) < 0:
            return
        rl.set_shader_value(
            shader,
            int(location),
            rl.ffi.new("float *", float(value)),
            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
        )

    @staticmethod
    def _set_shader_vec4(shader: rl.Shader, location: int, x: float, y: float, z: float, w: float) -> None:
        if int(location) < 0:
            return
        rl.set_shader_value(
            shader,
            int(location),
            rl.ffi.new("float[4]", [float(x), float(y), float(z), float(w)]),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
        )

    @staticmethod
    def _emit_probe_quad(*, x: float, y: float) -> None:
        x0 = float(x)
        y0 = float(y)
        x1 = x0 + 1.0
        y1 = y0 + 1.0
        rl.rl_color4ub(255, 255, 255, 1)
        rl.rl_tex_coord2f(0.0, 0.0)
        rl.rl_vertex2f(x0, y0)
        rl.rl_color4ub(255, 255, 255, 1)
        rl.rl_tex_coord2f(1.0, 0.0)
        rl.rl_vertex2f(x1, y0)
        rl.rl_color4ub(255, 255, 255, 1)
        rl.rl_tex_coord2f(1.0, 1.0)
        rl.rl_vertex2f(x1, y1)
        rl.rl_color4ub(255, 255, 255, 1)
        rl.rl_tex_coord2f(0.0, 1.0)
        rl.rl_vertex2f(x0, y1)

    def _run_quad_batch_probe(self, *, quads: int, texture_id: int) -> tuple[int | None, int]:
        requested_quads = max(1, int(quads))
        first_flush_quad: int | None = None
        flush_count = 0

        rl.rl_set_texture(int(texture_id))
        rl.rl_begin(rd.RL_QUADS)
        for idx in range(requested_quads):
            if bool(rl.rl_check_render_batch_limit(4)):
                flush_count += 1
                if first_flush_quad is None:
                    first_flush_quad = int(idx + 1)
            x = -12000.0 + float(idx % 256) * 1.5
            y = -12000.0 + float(idx // 256) * 1.5
            self._emit_probe_quad(x=x, y=y)
        rl.rl_end()
        rl.rl_set_texture(0)
        return first_flush_quad, int(flush_count)

    def _run_batch_probe(self) -> BatchProbeResult:
        requested_quads = max(1, int(self._batch_probe_quads))
        start_time = time.perf_counter()

        untextured_first_flush, untextured_flush_count = self._run_quad_batch_probe(
            quads=requested_quads,
            texture_id=0,
        )

        texture = self._projs_texture
        textured_available = texture is not None
        textured_first_flush: int | None = None
        textured_flush_count = 0
        if texture is not None:
            textured_first_flush, textured_flush_count = self._run_quad_batch_probe(
                quads=requested_quads,
                texture_id=int(texture.id),
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return BatchProbeResult(
            requested_quads=int(requested_quads),
            untextured_first_flush_quad=untextured_first_flush,
            untextured_flush_count=int(untextured_flush_count),
            textured_available=bool(textured_available),
            textured_first_flush_quad=textured_first_flush,
            textured_flush_count=int(textured_flush_count),
            elapsed_ms=float(elapsed_ms),
        )

    @staticmethod
    def _format_flush_quad(value: int | None) -> str:
        if value is None:
            return "none"
        return str(int(value))

    def _draw_projectile_body_sprites(self, preps: Sequence[_RenderPrep], *, streak_rgb: tuple[float, float, float]) -> int:
        texture = self._projs_texture
        if texture is None:
            return 0

        body_calls = 0
        sprite_scale = float(self._effect_scale)
        for prep in preps:
            for offset in prep.offsets:
                seg_alpha = self._segment_alpha(offset=float(offset), plan=prep.plan, base_alpha=prep.base_alpha)
                if seg_alpha <= 1e-3:
                    continue
                sample_t = float(offset) / prep.dist_units
                sample_pos = prep.preview.origin_screen + prep.ray * sample_t
                tint = RGBA(streak_rgb[0], streak_rgb[1], streak_rgb[2], seg_alpha).to_rl()
                self._draw_atlas_sprite(
                    texture,
                    grid=4,
                    frame=2,
                    pos=sample_pos,
                    scale=sprite_scale,
                    rotation_rad=prep.rotation_rad,
                    tint=tint,
                )
                body_calls += 1
        return int(body_calls)

    def _draw_projectile_body_shader_gemini_2(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
    ) -> tuple[int, bool]:
        shader = _get_beam_gemini_2_shader()
        if shader is None:
            return self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb), True

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)
        params = self._shader_gemini_2_params

        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE) * float(self._effect_scale) * float(SHADER_GEMINI_2_RADIUS_EXPAND),
        )
        step_screen = max(1e-6, float(self._beam_step_units()) * float(self._distance_to_screen_scale))
        step_uv = max(1e-4, float(step_screen) / float(radius))
        cover_len, halo_w, cap_scale = self._gemini_2_body_shape_params()

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_GEMINI_2_APPROX_A_LOC, float(params.approx_a))
        self._set_shader_float(shader, _BEAM_GEMINI_2_APPROX_B_LOC, float(params.approx_b))
        self._set_shader_float(shader, _BEAM_GEMINI_2_APPROX_C_LOC, float(params.approx_c))
        self._set_shader_float(shader, _BEAM_GEMINI_2_INTENSITY_GAIN_LOC, float(params.intensity_gain))
        self._set_shader_float(shader, _BEAM_GEMINI_2_STEP_UV_LOC, float(step_uv))
        self._set_shader_float(shader, _BEAM_GEMINI_2_COVER_LEN_LOC, float(cover_len))
        self._set_shader_float(shader, _BEAM_GEMINI_2_HALO_W_LOC, float(halo_w))
        self._set_shader_float(shader, _BEAM_GEMINI_2_CAP_SCALE_LOC, float(cap_scale))
        self._set_shader_vec4(shader, _BEAM_GEMINI_2_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            if not prep.offsets:
                continue

            s0 = float(prep.plan.start)
            s1 = float(prep.dist_units)
            if s1 - s0 <= 1e-6:
                continue

            t0 = s0 / prep.dist_units
            t1 = 1.0
            p0 = prep.preview.origin_screen + prep.ray * t0
            p1 = prep.preview.origin_screen + prep.ray * t1
            direction, length = (p1 - p0).normalized_with_length()
            if length <= 1e-6:
                continue

            head_alpha = self._u8(prep.base_alpha)
            if head_alpha <= 0:
                continue

            side = direction.perp_left() * radius

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha: int, u_len: float) -> None:
                rl.rl_color4ub(r, g, b, int(alpha))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

            # Single analytic quad encompassing body + tail cap + head cap
            u_len = length / radius
            tail_end = p0 - direction * radius
            head_end = p1 + direction * radius

            push(tail_end - side, uv_x=-1.0, uv_y=-1.0, alpha=head_alpha, u_len=u_len)
            push(tail_end + side, uv_x=-1.0, uv_y=1.0, alpha=head_alpha, u_len=u_len)
            push(head_end + side, uv_x=u_len + 1.0, uv_y=1.0, alpha=head_alpha, u_len=u_len)
            push(head_end - side, uv_x=u_len + 1.0, uv_y=-1.0, alpha=head_alpha, u_len=u_len)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count), False

    def _draw_projectile_body_shader_stamped_analytic(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
    ) -> tuple[int, bool]:
        shader = _get_beam_stamped_analytic_shader()
        if shader is None:
            return self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb), True

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)
        radius = max(0.001, float(SHADER_STAMP_ANALYTIC_RADIUS_SCALE) * float(self._effect_scale))

        body_calls = 0
        rl.begin_shader_mode(shader)
        self._set_shader_vec4(shader, _BEAM_STAMPED_ANALYTIC_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            direction = Vec2.from_angle(prep.rotation_rad)
            side = direction.perp_left() * radius
            forward = direction * radius
            for offset in prep.offsets:
                seg_alpha = self._segment_alpha(offset=float(offset), plan=prep.plan, base_alpha=prep.base_alpha)
                alpha_u8 = self._u8(seg_alpha)
                if alpha_u8 <= 0:
                    continue
                sample_t = float(offset) / prep.dist_units
                center = prep.preview.origin_screen + prep.ray * sample_t

                p0 = center - forward - side
                p1 = center - forward + side
                p2 = center + forward + side
                p3 = center + forward - side

                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(-1.0, -1.0)
                rl.rl_vertex3f(float(p0.x), float(p0.y), -1.0)
                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(-1.0, 1.0)
                rl.rl_vertex3f(float(p1.x), float(p1.y), -1.0)
                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(1.0, 1.0)
                rl.rl_vertex3f(float(p2.x), float(p2.y), -1.0)
                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(1.0, -1.0)
                rl.rl_vertex3f(float(p3.x), float(p3.y), -1.0)
                body_calls += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(body_calls), False

    def _draw_projectile_body_shader_stamped_virtual(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
    ) -> tuple[int, bool]:
        shader = _get_beam_stamped_virtual_shader()
        if shader is None:
            return self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb), True

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)
        radius = max(0.001, float(SHADER_STAMP_ANALYTIC_RADIUS_SCALE) * float(self._effect_scale))
        step_screen = max(1e-6, float(self._beam_step_units()) * float(self._distance_to_screen_scale))
        step_uv = max(1e-4, float(step_screen) / float(radius))
        stamp_scale = float(SHADER_STAMP_VIRTUAL_PROFILE_A_DEFAULT)
        stamp_decay = float(-SHADER_STAMP_VIRTUAL_PROFILE_LINEAR_DEFAULT)
        stamp_quad = float(SHADER_STAMP_VIRTUAL_PROFILE_QUAD_DEFAULT)
        stamp_offset = float(SHADER_STAMP_VIRTUAL_PROFILE_OFFSET_DEFAULT)
        core_flat_step_fraction = float(SHADER_STAMP_VIRTUAL_CORE_FLAT_STEP_FRACTION_DEFAULT)
        core_support_weight = float(SHADER_STAMP_VIRTUAL_CORE_SUPPORT_WEIGHT_DEFAULT)

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_vec4(shader, _BEAM_STAMPED_VIRTUAL_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        self._set_shader_float(shader, _BEAM_STAMPED_VIRTUAL_STEP_UV_LOC, float(step_uv))
        self._set_shader_float(shader, _BEAM_STAMPED_VIRTUAL_STAMP_SCALE_LOC, float(stamp_scale))
        self._set_shader_float(shader, _BEAM_STAMPED_VIRTUAL_STAMP_DECAY_LOC, float(stamp_decay))
        self._set_shader_float(shader, _BEAM_STAMPED_VIRTUAL_STAMP_QUAD_LOC, float(stamp_quad))
        self._set_shader_float(shader, _BEAM_STAMPED_VIRTUAL_STAMP_OFFSET_LOC, float(stamp_offset))
        self._set_shader_float(
            shader,
            _BEAM_STAMPED_VIRTUAL_CORE_FLAT_STEP_FRACTION_LOC,
            float(core_flat_step_fraction),
        )
        self._set_shader_float(
            shader,
            _BEAM_STAMPED_VIRTUAL_CORE_SUPPORT_WEIGHT_LOC,
            float(core_support_weight),
        )
        self._set_shader_float(
            shader,
            _BEAM_STAMPED_VIRTUAL_INTENSITY_GAIN_LOC,
            float(SHADER_STAMP_VIRTUAL_INTENSITY_GAIN_DEFAULT),
        )
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            if not prep.offsets:
                continue

            s0 = float(prep.plan.start)
            s1 = float(prep.dist_units)
            if s1 - s0 <= 1e-6:
                continue

            t0 = s0 / prep.dist_units
            t1 = 1.0
            p0 = prep.preview.origin_screen + prep.ray * t0
            p1 = prep.preview.origin_screen + prep.ray * t1
            direction, length = (p1 - p0).normalized_with_length()
            if length <= 1e-6:
                continue

            alpha_u8 = self._u8(prep.base_alpha)
            if alpha_u8 <= 0:
                continue

            side = direction.perp_left() * radius
            u_len = float(length) / float(radius)
            tail_end = p0 - direction * radius
            head_end = p1 + direction * radius

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha: int, u_len_value: float) -> None:
                rl.rl_color4ub(r, g, b, int(alpha))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len_value))

            push(tail_end - side, uv_x=-1.0, uv_y=-1.0, alpha=alpha_u8, u_len_value=u_len)
            push(tail_end + side, uv_x=-1.0, uv_y=1.0, alpha=alpha_u8, u_len_value=u_len)
            push(head_end + side, uv_x=u_len + 1.0, uv_y=1.0, alpha=alpha_u8, u_len_value=u_len)
            push(head_end - side, uv_x=u_len + 1.0, uv_y=-1.0, alpha=alpha_u8, u_len_value=u_len)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count), False

    def _draw_projectile_body_shader_ext_claude(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
    ) -> tuple[int, bool]:
        shader = _get_beam_ext_claude_shader()
        if shader is None:
            return self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb), True

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)
        params = self._shader_ext_claude_params

        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE) * float(self._effect_scale) * float(SHADER_GEMINI_2_RADIUS_EXPAND),
        )

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_APPROX_A_LOC, float(params.approx_a))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_APPROX_B_LOC, float(params.approx_b))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_APPROX_C_LOC, float(params.approx_c))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_INTENSITY_GAIN_LOC, float(params.intensity_gain))
        self._set_shader_float(
            shader,
            _BEAM_EXT_CLAUDE_LONGITUDINAL_GAMMA_LOC,
            float(params.longitudinal_gamma),
        )
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_RADIUS_TAPER_LOC, float(params.radius_taper))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_CORE_WEIGHT_LOC, float(params.core_weight))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_HALO_DECAY_LOC, float(params.halo_decay))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_CAP_SOFTNESS_LOC, float(params.cap_softness))
        self._set_shader_vec4(shader, _BEAM_EXT_CLAUDE_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            if not prep.offsets:
                continue

            s0 = float(prep.plan.start)
            s1 = float(prep.dist_units)
            if s1 - s0 <= 1e-6:
                continue

            t0 = s0 / prep.dist_units
            p0 = prep.preview.origin_screen + prep.ray * t0
            p1 = prep.preview.head_screen
            direction, length = (p1 - p0).normalized_with_length()
            if length <= 1e-6:
                continue

            head_alpha = self._u8(prep.base_alpha)
            if head_alpha <= 0:
                continue

            side = direction.perp_left() * radius

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha: int, u_len: float) -> None:
                rl.rl_color4ub(r, g, b, int(alpha))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

            # Single analytic quad encompassing body + tail cap + head cap.
            u_len = length / radius
            tail_end = p0 - direction * radius
            head_end = p1 + direction * radius

            push(tail_end - side, uv_x=-1.0, uv_y=-1.0, alpha=head_alpha, u_len=u_len)
            push(tail_end + side, uv_x=-1.0, uv_y=1.0, alpha=head_alpha, u_len=u_len)
            push(head_end + side, uv_x=u_len + 1.0, uv_y=1.0, alpha=head_alpha, u_len=u_len)
            push(head_end - side, uv_x=u_len + 1.0, uv_y=-1.0, alpha=head_alpha, u_len=u_len)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count), False

    def _draw_projectile_head_shader_ext_claude(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
        is_fire: bool,
    ) -> int:
        if not bool(self._head_render_enabled):
            return 0

        shader = _get_beam_ext_claude_shader()
        if shader is None:
            return 0

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)

        params = self._shader_ext_claude_params
        approx_a = clamp(
            float(params.approx_a) * (1.1 if bool(is_fire) else 1.05),
            SHADER_GEMINI_2_APPROX_A_MIN,
            SHADER_GEMINI_2_APPROX_A_MAX,
        )
        approx_b = clamp(
            float(params.approx_b) * (0.8 if bool(is_fire) else 0.85),
            SHADER_GEMINI_2_APPROX_B_MIN,
            SHADER_GEMINI_2_APPROX_B_MAX,
        )
        approx_c = clamp(
            float(params.approx_c),
            SHADER_GEMINI_2_APPROX_C_MIN,
            SHADER_GEMINI_2_APPROX_C_MAX,
        )
        intensity_gain = clamp(
            float(params.intensity_gain) * (1.22 if bool(is_fire) else 1.08),
            SHADER_GEMINI_2_INTENSITY_GAIN_MIN,
            SHADER_GEMINI_2_INTENSITY_GAIN_MAX,
        )
        cap_softness = max(0.05, float(params.cap_softness))

        head_radius_multiplier = (
            float(SHADER_GEMINI_2_HEAD_FIRE_RADIUS_MULTIPLIER)
            if bool(is_fire)
            else float(SHADER_GEMINI_2_HEAD_RADIUS_MULTIPLIER)
        )
        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE)
            * float(self._effect_scale)
            * float(SHADER_GEMINI_2_RADIUS_EXPAND)
            * head_radius_multiplier,
        )

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_APPROX_A_LOC, float(approx_a))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_APPROX_B_LOC, float(approx_b))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_APPROX_C_LOC, float(approx_c))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_INTENSITY_GAIN_LOC, float(intensity_gain))
        self._set_shader_float(
            shader,
            _BEAM_EXT_CLAUDE_LONGITUDINAL_GAMMA_LOC,
            float(params.longitudinal_gamma),
        )
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_RADIUS_TAPER_LOC, float(params.radius_taper))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_CORE_WEIGHT_LOC, float(params.core_weight))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_HALO_DECAY_LOC, float(params.halo_decay))
        self._set_shader_float(shader, _BEAM_EXT_CLAUDE_CAP_SOFTNESS_LOC, float(cap_softness))
        self._set_shader_vec4(shader, _BEAM_EXT_CLAUDE_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            head_alpha = self._u8(prep.base_alpha)
            if head_alpha <= 0:
                continue

            direction = Vec2.from_angle(prep.rotation_rad)
            side = direction.perp_left() * radius
            forward = direction * radius
            center = prep.preview.head_screen

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha_u8: int = head_alpha) -> None:
                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

            push(center - forward - side, uv_x=-1.0, uv_y=-1.0)
            push(center - forward + side, uv_x=-1.0, uv_y=1.0)
            push(center + forward + side, uv_x=1.0, uv_y=1.0)
            push(center + forward - side, uv_x=1.0, uv_y=-1.0)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count)

    def _draw_projectile_body_shader_ext_gemini(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
    ) -> tuple[int, bool]:
        shader = _get_beam_ext_gemini_shader()
        if shader is None:
            return self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb), True

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)
        params = self._shader_ext_gemini_params

        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE) * float(self._effect_scale) * float(SHADER_GEMINI_2_RADIUS_EXPAND),
        )

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_HALO_A_LOC, float(params.halo_a))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_HALO_B_LOC, float(params.halo_b))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_CORE_A_LOC, float(params.core_a))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_CORE_B_LOC, float(params.core_b))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_APPROX_C_LOC, float(params.approx_c))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_INTENSITY_GAIN_LOC, float(params.intensity_gain))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_TAIL_WIDTH_LOC, float(params.tail_width))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_CAP_SCALE_LOC, float(params.cap_scale))
        self._set_shader_vec4(shader, _BEAM_EXT_GEMINI_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            if not prep.offsets:
                continue

            s0 = float(prep.plan.start)
            s1 = float(prep.dist_units)
            if s1 - s0 <= 1e-6:
                continue

            t0 = s0 / prep.dist_units
            p0 = prep.preview.origin_screen + prep.ray * t0
            p1 = prep.preview.head_screen
            direction, length = (p1 - p0).normalized_with_length()
            if length <= 1e-6:
                continue

            head_alpha = self._u8(prep.base_alpha)
            if head_alpha <= 0:
                continue

            side = direction.perp_left() * radius

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha: int, u_len: float) -> None:
                rl.rl_color4ub(r, g, b, int(alpha))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len))

            u_len = length / radius
            tail_end = p0 - direction * radius
            head_end = p1 + direction * radius

            push(tail_end - side, uv_x=-1.0, uv_y=-1.0, alpha=head_alpha, u_len=u_len)
            push(tail_end + side, uv_x=-1.0, uv_y=1.0, alpha=head_alpha, u_len=u_len)
            push(head_end + side, uv_x=u_len + 1.0, uv_y=1.0, alpha=head_alpha, u_len=u_len)
            push(head_end - side, uv_x=u_len + 1.0, uv_y=-1.0, alpha=head_alpha, u_len=u_len)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count), False

    def _draw_projectile_head_shader_ext_gemini(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
        is_fire: bool,
    ) -> int:
        if not bool(self._head_render_enabled):
            return 0

        shader = _get_beam_ext_gemini_shader()
        if shader is None:
            return 0

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)

        params = self._shader_ext_gemini_params
        halo_a = clamp(
            float(params.halo_a) * (1.1 if bool(is_fire) else 1.05),
            SHADER_GEMINI_2_APPROX_A_MIN,
            SHADER_GEMINI_2_APPROX_A_MAX,
        )
        halo_b = clamp(
            float(params.halo_b) * (0.8 if bool(is_fire) else 0.85),
            SHADER_GEMINI_2_APPROX_B_MIN,
            SHADER_GEMINI_2_APPROX_B_MAX,
        )
        approx_c = clamp(
            float(params.approx_c),
            SHADER_GEMINI_2_APPROX_C_MIN,
            SHADER_GEMINI_2_APPROX_C_MAX,
        )
        intensity_gain = clamp(
            float(params.intensity_gain) * (1.22 if bool(is_fire) else 1.08),
            SHADER_GEMINI_2_INTENSITY_GAIN_MIN,
            SHADER_GEMINI_2_INTENSITY_GAIN_MAX,
        )

        head_radius_multiplier = (
            float(SHADER_GEMINI_2_HEAD_FIRE_RADIUS_MULTIPLIER)
            if bool(is_fire)
            else float(SHADER_GEMINI_2_HEAD_RADIUS_MULTIPLIER)
        )
        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE)
            * float(self._effect_scale)
            * float(SHADER_GEMINI_2_RADIUS_EXPAND)
            * head_radius_multiplier,
        )

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_HALO_A_LOC, float(halo_a))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_HALO_B_LOC, float(halo_b))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_CORE_A_LOC, float(params.core_a))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_CORE_B_LOC, float(params.core_b))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_APPROX_C_LOC, float(approx_c))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_INTENSITY_GAIN_LOC, float(intensity_gain))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_TAIL_WIDTH_LOC, float(params.tail_width))
        self._set_shader_float(shader, _BEAM_EXT_GEMINI_CAP_SCALE_LOC, float(params.cap_scale))
        self._set_shader_vec4(shader, _BEAM_EXT_GEMINI_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            head_alpha = self._u8(prep.base_alpha)
            if head_alpha <= 0:
                continue

            direction = Vec2.from_angle(prep.rotation_rad)
            side = direction.perp_left() * radius
            forward = direction * radius
            center = prep.preview.head_screen

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha_u8: int = head_alpha) -> None:
                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

            push(center - forward - side, uv_x=-1.0, uv_y=-1.0)
            push(center - forward + side, uv_x=-1.0, uv_y=1.0)
            push(center + forward + side, uv_x=1.0, uv_y=1.0)
            push(center + forward - side, uv_x=1.0, uv_y=-1.0)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count)

    def _draw_projectile_body_shader_ext_gpt_pro(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
    ) -> tuple[int, bool]:
        shader = _get_beam_ext_gpt_pro_shader()
        if shader is None:
            return self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb), True

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)
        params = self._shader_ext_gpt_pro_params

        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE) * float(self._effect_scale) * float(SHADER_GEMINI_2_RADIUS_EXPAND),
        )
        step_screen = max(1e-6, float(self._beam_step_units()) * float(self._distance_to_screen_scale))
        step_uv = max(1e-4, float(step_screen) / float(radius))

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_APPROX_A_LOC, float(params.approx_a))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_APPROX_B_LOC, float(params.approx_b))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_APPROX_C_LOC, float(params.approx_c))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_INTENSITY_GAIN_LOC, float(params.intensity_gain))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_STEP_UV_LOC, float(step_uv))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_COVER_LEN_LOC, float(params.cover_len))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_HALO_W_LOC, float(params.halo_w))
        self._set_shader_vec4(shader, _BEAM_EXT_GPT_PRO_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            if not prep.offsets:
                continue

            s0 = float(prep.plan.start)
            s1 = float(prep.dist_units)
            if s1 - s0 <= 1e-6:
                continue

            t0 = s0 / prep.dist_units
            p0 = prep.preview.origin_screen + prep.ray * t0
            p1 = prep.preview.head_screen
            direction, length = (p1 - p0).normalized_with_length()
            if length <= 1e-6:
                continue

            alpha_u8 = self._u8(prep.base_alpha)
            if alpha_u8 <= 0:
                continue

            side = direction.perp_left() * radius
            u_len = float(length) / float(radius)
            tail_end = p0 - direction * radius
            head_end = p1 + direction * radius

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha: int = alpha_u8, u_len_value: float = u_len) -> None:
                rl.rl_color4ub(r, g, b, int(alpha))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), float(u_len_value))

            push(tail_end - side, uv_x=-1.0, uv_y=-1.0)
            push(tail_end + side, uv_x=-1.0, uv_y=1.0)
            push(head_end + side, uv_x=u_len + 1.0, uv_y=1.0)
            push(head_end - side, uv_x=u_len + 1.0, uv_y=-1.0)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count), False

    def _draw_projectile_head_shader_ext_gpt_pro(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
        is_fire: bool,
    ) -> int:
        if not bool(self._head_render_enabled):
            return 0

        shader = _get_beam_ext_gpt_pro_shader()
        if shader is None:
            return 0

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)

        params = self._shader_ext_gpt_pro_params
        approx_a = clamp(
            float(params.approx_a) * (1.1 if bool(is_fire) else 1.05),
            SHADER_GEMINI_2_APPROX_A_MIN,
            SHADER_GEMINI_2_APPROX_A_MAX,
        )
        approx_b = clamp(
            float(params.approx_b) * (0.8 if bool(is_fire) else 0.85),
            SHADER_GEMINI_2_APPROX_B_MIN,
            SHADER_GEMINI_2_APPROX_B_MAX,
        )
        approx_c = clamp(
            float(params.approx_c),
            SHADER_GEMINI_2_APPROX_C_MIN,
            SHADER_GEMINI_2_APPROX_C_MAX,
        )
        intensity_gain = clamp(
            float(params.intensity_gain) * (1.22 if bool(is_fire) else 1.08),
            SHADER_GEMINI_2_INTENSITY_GAIN_MIN,
            SHADER_GEMINI_2_INTENSITY_GAIN_MAX,
        )

        head_radius_multiplier = (
            float(SHADER_GEMINI_2_HEAD_FIRE_RADIUS_MULTIPLIER)
            if bool(is_fire)
            else float(SHADER_GEMINI_2_HEAD_RADIUS_MULTIPLIER)
        )
        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE)
            * float(self._effect_scale)
            * float(SHADER_GEMINI_2_RADIUS_EXPAND)
            * head_radius_multiplier,
        )
        step_screen = max(1e-6, float(self._beam_step_units()) * float(self._distance_to_screen_scale))
        step_uv = max(1e-4, float(step_screen) / float(radius))

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_APPROX_A_LOC, float(approx_a))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_APPROX_B_LOC, float(approx_b))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_APPROX_C_LOC, float(approx_c))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_INTENSITY_GAIN_LOC, float(intensity_gain))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_STEP_UV_LOC, float(step_uv))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_COVER_LEN_LOC, float(params.cover_len))
        self._set_shader_float(shader, _BEAM_EXT_GPT_PRO_HALO_W_LOC, float(params.halo_w))
        self._set_shader_vec4(shader, _BEAM_EXT_GPT_PRO_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            alpha_u8 = self._u8(prep.base_alpha)
            if alpha_u8 <= 0:
                continue

            direction = Vec2.from_angle(prep.rotation_rad)
            side = direction.perp_left() * radius
            forward = direction * radius
            center = prep.preview.head_screen

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha: int = alpha_u8) -> None:
                rl.rl_color4ub(r, g, b, int(alpha))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

            push(center - forward - side, uv_x=-1.0, uv_y=-1.0)
            push(center - forward + side, uv_x=-1.0, uv_y=1.0)
            push(center + forward + side, uv_x=1.0, uv_y=1.0)
            push(center + forward - side, uv_x=1.0, uv_y=-1.0)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count)

    def _draw_projectile_head_shader_stamped_analytic(self, preps: Sequence[_RenderPrep], *, is_fire: bool) -> int:
        del is_fire
        if not bool(self._head_render_enabled):
            return 0

        shader = _get_beam_stamped_analytic_shader()
        if shader is None:
            return 0

        head_calls = 0
        radius_high = max(0.001, float(SHADER_STAMP_ANALYTIC_RADIUS_SCALE) * float(self._effect_scale))
        radius_low = float(SHADER_STAMP_ANALYTIC_RADIUS_SCALE)
        rl.begin_shader_mode(shader)
        self._set_shader_vec4(shader, _BEAM_STAMPED_ANALYTIC_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            life = float(prep.preview.life)
            if life >= 0.4:
                rgb = (1.0, 1.0, 0.7)
                radius = radius_high
            else:
                rgb = (0.5, 0.6, 1.0)
                radius = radius_low

            alpha_u8 = self._u8(prep.base_alpha)
            if alpha_u8 <= 0:
                continue

            r = int(clamp(rgb[0] * 255.0, 0.0, 255.0) + 0.5)
            g = int(clamp(rgb[1] * 255.0, 0.0, 255.0) + 0.5)
            b = int(clamp(rgb[2] * 255.0, 0.0, 255.0) + 0.5)
            direction = Vec2.from_angle(prep.rotation_rad)
            side = direction.perp_left() * radius
            forward = direction * radius
            center = prep.preview.head_screen

            p0 = center - forward - side
            p1 = center - forward + side
            p2 = center + forward + side
            p3 = center + forward - side
            rl.rl_color4ub(r, g, b, int(alpha_u8))
            rl.rl_tex_coord2f(-1.0, -1.0)
            rl.rl_vertex3f(float(p0.x), float(p0.y), -1.0)
            rl.rl_color4ub(r, g, b, int(alpha_u8))
            rl.rl_tex_coord2f(-1.0, 1.0)
            rl.rl_vertex3f(float(p1.x), float(p1.y), -1.0)
            rl.rl_color4ub(r, g, b, int(alpha_u8))
            rl.rl_tex_coord2f(1.0, 1.0)
            rl.rl_vertex3f(float(p2.x), float(p2.y), -1.0)
            rl.rl_color4ub(r, g, b, int(alpha_u8))
            rl.rl_tex_coord2f(1.0, -1.0)
            rl.rl_vertex3f(float(p3.x), float(p3.y), -1.0)
            head_calls += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(head_calls)

    def _draw_projectile_head_shader_gemini_2(
        self,
        preps: Sequence[_RenderPrep],
        *,
        streak_rgb: tuple[float, float, float],
        is_fire: bool,
    ) -> int:
        if not bool(self._head_render_enabled):
            return 0

        shader = _get_beam_gemini_2_shader()
        if shader is None:
            return 0

        r = int(clamp(streak_rgb[0] * 255.0, 0.0, 255.0) + 0.5)
        g = int(clamp(streak_rgb[1] * 255.0, 0.0, 255.0) + 0.5)
        b = int(clamp(streak_rgb[2] * 255.0, 0.0, 255.0) + 0.5)

        params = self._shader_gemini_2_params
        _, halo_w_body, _ = self._gemini_2_body_shape_params()
        approx_a = clamp(
            float(params.approx_a) * (1.1 if bool(is_fire) else 1.05),
            SHADER_GEMINI_2_APPROX_A_MIN,
            SHADER_GEMINI_2_APPROX_A_MAX,
        )
        approx_b = clamp(
            float(params.approx_b) * (0.8 if bool(is_fire) else 0.85),
            SHADER_GEMINI_2_APPROX_B_MIN,
            SHADER_GEMINI_2_APPROX_B_MAX,
        )
        approx_c = clamp(
            float(params.approx_c) * 1.0,
            SHADER_GEMINI_2_APPROX_C_MIN,
            SHADER_GEMINI_2_APPROX_C_MAX,
        )
        intensity_gain = clamp(
            float(params.intensity_gain) * (1.22 if bool(is_fire) else 1.08),
            SHADER_GEMINI_2_INTENSITY_GAIN_MIN,
            SHADER_GEMINI_2_INTENSITY_GAIN_MAX,
        )

        head_radius_multiplier = (
            float(SHADER_GEMINI_2_HEAD_FIRE_RADIUS_MULTIPLIER)
            if bool(is_fire)
            else float(SHADER_GEMINI_2_HEAD_RADIUS_MULTIPLIER)
        )
        radius = max(
            0.001,
            float(SHADER_GEMINI_2_RADIUS_SCALE)
            * float(self._effect_scale)
            * float(SHADER_GEMINI_2_RADIUS_EXPAND)
            * head_radius_multiplier,
        )

        quad_count = 0
        rl.begin_shader_mode(shader)
        self._set_shader_float(shader, _BEAM_GEMINI_2_APPROX_A_LOC, float(approx_a))
        self._set_shader_float(shader, _BEAM_GEMINI_2_APPROX_B_LOC, float(approx_b))
        self._set_shader_float(shader, _BEAM_GEMINI_2_APPROX_C_LOC, float(approx_c))
        self._set_shader_float(shader, _BEAM_GEMINI_2_INTENSITY_GAIN_LOC, float(intensity_gain))
        self._set_shader_float(shader, _BEAM_GEMINI_2_STEP_UV_LOC, 1.0)
        self._set_shader_float(shader, _BEAM_GEMINI_2_COVER_LEN_LOC, float(SHADER_GEMINI_2_COVER_LEN_DEFAULT))
        self._set_shader_float(shader, _BEAM_GEMINI_2_HALO_W_LOC, float(halo_w_body))
        self._set_shader_float(shader, _BEAM_GEMINI_2_CAP_SCALE_LOC, float(SHADER_GEMINI_2_CAP_SCALE_DEFAULT))
        self._set_shader_vec4(shader, _BEAM_GEMINI_2_COLOR_LOC, 1.0, 1.0, 1.0, 1.0)
        rl.rl_set_texture(0)
        rl.rl_begin(rd.RL_QUADS)
        for prep in preps:
            head_alpha = self._u8(prep.base_alpha)
            if head_alpha <= 0:
                continue

            direction = Vec2.from_angle(prep.rotation_rad)
            side = direction.perp_left() * radius
            forward = direction * radius
            center = prep.preview.head_screen

            def push(pos: Vec2, *, uv_x: float, uv_y: float, alpha_u8: int = head_alpha) -> None:
                rl.rl_color4ub(r, g, b, int(alpha_u8))
                rl.rl_tex_coord2f(float(uv_x), float(uv_y))
                rl.rl_vertex3f(float(pos.x), float(pos.y), -1.0)

            push(center - forward - side, uv_x=-1.0, uv_y=-1.0)
            push(center - forward + side, uv_x=-1.0, uv_y=1.0)
            push(center + forward + side, uv_x=1.0, uv_y=1.0)
            push(center + forward - side, uv_x=1.0, uv_y=-1.0)
            quad_count += 1
        rl.rl_end()
        rl.rl_set_texture(0)
        rl.end_shader_mode()
        return int(quad_count)

    def _draw_projectile_heads(
        self,
        preps: Sequence[_RenderPrep],
        *,
        is_fire: bool,
    ) -> tuple[int, int]:
        if not bool(self._head_render_enabled):
            return 0, 0
        texture = self._projs_texture
        if texture is None:
            return 0, 0

        head_calls = 0
        overlay_calls = 0
        head_rgb = (1.0, 1.0, 0.7)

        for prep in preps:
            life = float(prep.preview.life)
            if life >= 0.4:
                head_tint = RGBA(head_rgb[0], head_rgb[1], head_rgb[2], prep.base_alpha).to_rl()
                self._draw_atlas_sprite(
                    texture,
                    grid=4,
                    frame=2,
                    pos=prep.preview.head_screen,
                    scale=float(self._effect_scale),
                    rotation_rad=prep.rotation_rad,
                    tint=head_tint,
                )
                head_calls += 1

                if is_fire:
                    if self._draw_fire_overlay(prep.preview, alpha=1.0, rotation_rad=prep.rotation_rad):
                        overlay_calls += 1
            else:
                core_tint = RGBA(0.5, 0.6, 1.0, prep.base_alpha).to_rl()
                self._draw_atlas_sprite(
                    texture,
                    grid=4,
                    frame=2,
                    pos=prep.preview.head_screen,
                    scale=1.0,
                    rotation_rad=prep.rotation_rad,
                    tint=core_tint,
                )
                head_calls += 1

        return int(head_calls), int(overlay_calls)

    def _draw_projectiles(
        self,
        previews: Sequence[_PreviewProjectile],
        *,
        mode: BeamRenderMode,
    ) -> tuple[BeamRenderFrameResult, bool]:
        is_fire = bool(self._use_fire_profile)

        inputs: list[BeamCountInput] = []
        for preview in previews:
            ray = preview.head_screen - preview.origin_screen
            inputs.append(
                BeamCountInput(
                    plan=preview.plan,
                    life=float(preview.life),
                    screen_length_px=float(ray.length()),
                ),
            )

        baseline_counts = estimate_beam_frame_counts(
            inputs,
            mode=BeamRenderMode.BASELINE_SPRITE,
            is_fire=is_fire,
            draw_heads_enabled=bool(self._head_render_enabled),
        )

        texture = self._projs_texture
        if mode == BeamRenderMode.BASELINE_SPRITE and texture is None:
            empty = BeamDrawCounts(0, 0, 0, 0, 0)
            return BeamRenderFrameResult(current_counts=empty, baseline_counts=baseline_counts), False

        preps = self._build_render_preps(previews, mode=mode)
        current_estimated = estimate_beam_frame_counts(
            inputs,
            mode=mode,
            is_fire=is_fire,
            draw_heads_enabled=bool(self._head_render_enabled),
        )

        streak_rgb = (1.0, 0.6, 0.1) if is_fire else (0.5, 0.6, 1.0)

        shader_fallback = False
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        if mode == BeamRenderMode.BASELINE_SPRITE:
            body_calls = self._draw_projectile_body_sprites(preps, streak_rgb=streak_rgb)
            head_calls, overlay_calls = self._draw_projectile_heads(
                preps,
                is_fire=is_fire,
            )
        elif mode == BeamRenderMode.SHADER_STAMPED_VIRTUAL:
            body_calls, fallback = self._draw_projectile_body_shader_stamped_virtual(preps, streak_rgb=streak_rgb)
            shader_fallback = bool(fallback)
            if fallback:
                head_calls, overlay_calls = self._draw_projectile_heads(preps, is_fire=is_fire)
            else:
                head_calls = self._draw_projectile_head_shader_stamped_analytic(preps, is_fire=is_fire)
                overlay_calls = 0
        elif mode == BeamRenderMode.SHADER_EXT_CLAUDE:
            body_calls, fallback = self._draw_projectile_body_shader_ext_claude(preps, streak_rgb=streak_rgb)
            shader_fallback = bool(fallback)
            if fallback:
                head_calls, overlay_calls = self._draw_projectile_heads(preps, is_fire=is_fire)
            else:
                head_calls = self._draw_projectile_head_shader_ext_claude(
                    preps,
                    streak_rgb=streak_rgb,
                    is_fire=is_fire,
                )
                overlay_calls = 0
        elif mode == BeamRenderMode.SHADER_EXT_GEMINI:
            body_calls, fallback = self._draw_projectile_body_shader_ext_gemini(preps, streak_rgb=streak_rgb)
            shader_fallback = bool(fallback)
            if fallback:
                head_calls, overlay_calls = self._draw_projectile_heads(preps, is_fire=is_fire)
            else:
                head_calls = self._draw_projectile_head_shader_ext_gemini(
                    preps,
                    streak_rgb=streak_rgb,
                    is_fire=is_fire,
                )
                overlay_calls = 0
        elif mode == BeamRenderMode.SHADER_EXT_GPT_PRO:
            body_calls, fallback = self._draw_projectile_body_shader_ext_gpt_pro(preps, streak_rgb=streak_rgb)
            shader_fallback = bool(fallback)
            if fallback:
                head_calls, overlay_calls = self._draw_projectile_heads(preps, is_fire=is_fire)
            else:
                head_calls = self._draw_projectile_head_shader_ext_gpt_pro(
                    preps,
                    streak_rgb=streak_rgb,
                    is_fire=is_fire,
                )
                overlay_calls = 0
        elif mode == BeamRenderMode.SHADER_GEMINI_2:
            body_calls, fallback = self._draw_projectile_body_shader_gemini_2(preps, streak_rgb=streak_rgb)
            shader_fallback = bool(fallback)
            head_calls = self._draw_projectile_head_shader_gemini_2(preps, streak_rgb=streak_rgb, is_fire=is_fire)
            overlay_calls = 0
        else:
            body_calls = 0
            head_calls = 0
            overlay_calls = 0
        rl.end_blend_mode()

        current_counts = BeamDrawCounts(
            body_calls=int(body_calls),
            head_calls=int(head_calls),
            overlay_calls=int(overlay_calls),
            visible_segments=int(current_estimated.visible_segments),
            head_region_segments=int(current_estimated.head_region_segments),
        )
        return BeamRenderFrameResult(current_counts=current_counts, baseline_counts=baseline_counts), bool(shader_fallback)

    def _draw_segment_markers(self, preview: _PreviewProjectile) -> None:
        plan = preview.plan
        if plan is None:
            return
        dist_units = max(1e-6, float(preview.dist_units))
        ray = preview.head_screen - preview.origin_screen
        for offset in iter_beam_sample_offsets(plan):
            t = float(offset) / dist_units
            pos = preview.origin_screen + ray * t
            rl.draw_rectangle(int(pos.x) - 1, int(pos.y) - 1, 2, 2, SEGMENT_MARK)

    @staticmethod
    def _delta_percent(value: float, baseline: float) -> float | None:
        if abs(float(baseline)) <= 1e-6:
            return None
        return ((float(value) - float(baseline)) / float(baseline)) * 100.0

    def _draw_overlay(
        self,
        previews: Sequence[_PreviewProjectile],
        selected: _PreviewProjectile,
        *,
        render_result: BeamRenderFrameResult,
        beam_draw_ms: float,
        baseline_panel_result: BeamRenderFrameResult | None = None,
        baseline_panel_beam_draw_ms: float | None = None,
    ) -> None:
        margin = 14.0
        line_h = float(ui_line_height(self._small, scale=0.8))
        y = margin

        style_name = "fire" if self._use_fire_profile else "ion"
        ion_preset = self._active_ion_preset()
        cap_name = "256" if self._cap_enabled else "off"
        compare_label = "compare=side-by-side" if self._side_by_side_enabled and not self._bench_active else "compare=off"
        draw_ui_text(
            self._small,
            (
                f"beam-debug mode={_mode_label(self._render_mode)} preset={_preset_label(self._scenario_preset)} "
                f"style={style_name} ion_preset={ion_preset.key} {compare_label} "
                f"paused={'yes' if self._paused else 'no'} sim_speed={self._sim_speed:.2f}x"
            ),
            Vec2(margin, y),
            color=UI_TEXT,
            scale=0.8,
        )
        y += line_h
        draw_ui_text(
            self._small,
            f"bench={self._benchmark_progress_label()} frames_per_mode={self._bench_frames_per_mode}",
            Vec2(margin, y),
            color=UI_ACCENT if self._bench_active else UI_HINT,
            scale=0.8,
        )
        y += line_h
        draw_ui_text(
            self._small,
            (
                f"flags cap={'on' if self._cap_enabled else 'off'} "
                f"head={'on' if self._head_render_enabled else 'off'} "
                f"head_cap={self._head_cap_variant.value} "
                f"life_hi={'on' if self._force_life_high else 'off'} "
                f"markers={'all' if self._show_all_segment_markers else 'selected'} "
                f"geometry={'on' if self._show_geometry_overlay else 'off'}"
            ),
            Vec2(margin, y),
            color=UI_HINT,
            scale=0.8,
        )
        y += line_h
        draw_ui_text(
            self._small,
            (
                "Space pause/resume  Right step(when paused)  Esc close  P screenshot  "
                "F fire/ion  I cycle ion preset  C cap256  G force life>=0.4  H toggle heads  D cycle head-cap  M all markers  V geometry  "
                "X run batch-probe  Z auto-probe  J/U probe quads  N autofit-profile  0 reset shader  Q research/fitted"
            ),
            Vec2(margin, y),
            color=UI_HINT,
            scale=0.8,
        )
        y += line_h
        draw_ui_text(
            self._small,
            (
                "R cycle mode  Tab side-by-side  Y benchmark-run  1/2/3 presets  T reset stats  [ ] projectile count  , . select projectile  "
                "Up/Down base dist  PgUp/PgDn jitter  K/L effect_scale  -/= sim speed  Backspace reset  "
                "W-/S+ gain (exp profile locked)"
            ),
            Vec2(margin, y),
            color=UI_HINT,
            scale=0.8,
        )
        y += line_h + 4.0

        current = render_result.current_counts
        baseline = render_result.baseline_counts

        draw_ui_text(
            self._small,
            (
                f"projectiles={len(previews)} step={self._beam_step_units():.3f} effect_scale={self._effect_scale:.3f} "
                f"speed={self._projectile_speed_units_per_second():.1f}u/s "
                f"dist_scale={self._distance_scale_from_base():.3f} jitter={self._distance_jitter_units:.1f} cap={cap_name} "
                f"ion={ion_preset.label} ({ion_preset.note})"
            ),
            Vec2(margin, y),
            color=UI_TEXT,
            scale=0.8,
        )
        y += line_h
        shader_params = self._shader_gemini_2_params
        body_cover_len, body_halo_w, body_cap_scale = self._gemini_2_body_shape_params()
        draw_ui_text(
            self._small,
            (
                f"shader profile=clamp({shader_params.approx_a:.4f}*exp({shader_params.approx_b:.4f}*d)-{shader_params.approx_c:.4f},0,1) "
                f"gain={shader_params.intensity_gain:.3f} "
                f"cover={body_cover_len:.2f} halo_w={body_halo_w:.2f} cap_scale={body_cap_scale:.2f}"
            ),
            Vec2(margin, y),
            color=UI_HINT,
            scale=0.8,
        )
        y += line_h
        draw_ui_text(
            self._small,
            f"shader status: {self._shader_fit_status}",
            Vec2(margin, y),
            color=UI_HINT if "failed" not in self._shader_fit_status else UI_WARN,
            scale=0.8,
        )
        y += line_h
        reference = self._shader_reference_profile
        if reference is not None:
            draw_ui_text(
                self._small,
                (
                    f"shader reference: {reference.source} "
                    f"radius={reference.radius_px:.2f} centroid=({reference.centroid_x:.2f},{reference.centroid_y:.2f}) "
                    f"fit_elapsed_ms={self._shader_fit_elapsed_ms:.2f}"
                ),
                Vec2(margin, y),
                color=UI_HINT,
                scale=0.8,
            )
            y += line_h

        if baseline_panel_result is None:
            draw_ui_text(
                self._small,
                (
                    f"this frame calls total={current.total_calls} body={current.body_calls} head={current.head_calls} "
                    f"overlay={current.overlay_calls} beam_draw_ms={beam_draw_ms:.3f}"
                ),
                Vec2(margin, y),
                color=UI_ACCENT,
                scale=0.8,
            )
        else:
            baseline_current = baseline_panel_result.current_counts
            baseline_ms = 0.0 if baseline_panel_beam_draw_ms is None else float(baseline_panel_beam_draw_ms)
            delta_calls = self._delta_percent(float(current.total_calls), float(baseline_current.total_calls))
            delta_ms = self._delta_percent(float(beam_draw_ms), float(baseline_ms))
            delta_calls_str = "n/a" if delta_calls is None else f"{delta_calls:+.1f}%"
            delta_ms_str = "n/a" if delta_ms is None else f"{delta_ms:+.1f}%"
            draw_ui_text(
                self._small,
                (
                    f"this frame left(base) calls={baseline_current.total_calls} beam_ms={baseline_ms:.3f}  "
                    f"right({_mode_label(self._render_mode)}) calls={current.total_calls} beam_ms={beam_draw_ms:.3f}  "
                    f"d_calls={delta_calls_str} d_ms={delta_ms_str}"
                ),
                Vec2(margin, y),
                color=UI_ACCENT,
                scale=0.8,
            )
        y += line_h

        draw_ui_text(
            self._small,
            (
                f"segments current={current.visible_segments} baseline={baseline.visible_segments} "
                f"head-region current={current.head_region_segments} baseline={baseline.head_region_segments}"
            ),
            Vec2(margin, y),
            color=UI_TEXT,
            scale=0.8,
        )
        y += line_h

        if baseline.head_region_segments > 0 and float(current.head_region_segments) < float(baseline.head_region_segments) * 0.65:
            draw_ui_text(
                self._small,
                "parity warning: current mode uses >35% fewer near-head segments than baseline",
                Vec2(margin, y),
                color=UI_WARN,
                scale=0.8,
            )
            y += line_h
        if self._last_shader_fallback:
            draw_ui_text(
                self._small,
                f"{_mode_label(self._render_mode)} unavailable; using baseline sprite fallback",
                Vec2(margin, y),
                color=UI_WARN,
                scale=0.8,
            )
            y += line_h

        probe_mode = "auto" if self._batch_probe_auto else "off"
        draw_ui_text(
            self._small,
            f"batch probe mode={probe_mode} quads={self._batch_probe_quads}",
            Vec2(margin, y),
            color=UI_HINT,
            scale=0.8,
        )
        y += line_h
        if self._batch_probe_last is not None:
            probe = self._batch_probe_last
            draw_ui_text(
                self._small,
                (
                    f"probe untex first_flush_quad={self._format_flush_quad(probe.untextured_first_flush_quad)} "
                    f"flushes={probe.untextured_flush_count} elapsed_ms={probe.elapsed_ms:.3f}"
                ),
                Vec2(margin, y),
                color=UI_TEXT,
                scale=0.8,
            )
            y += line_h
            if probe.textured_available:
                draw_ui_text(
                    self._small,
                    (
                        f"probe tex first_flush_quad={self._format_flush_quad(probe.textured_first_flush_quad)} "
                        f"flushes={probe.textured_flush_count}"
                    ),
                    Vec2(margin, y),
                    color=UI_TEXT,
                    scale=0.8,
                )
            else:
                draw_ui_text(
                    self._small,
                    "probe tex unavailable (missing projs texture)",
                    Vec2(margin, y),
                    color=UI_WARN,
                    scale=0.8,
                )
            y += line_h

        y += 2.0
        draw_ui_text(self._small, "mode comparison (rolling window)", Vec2(margin, y), color=UI_TEXT, scale=0.8)
        y += line_h

        baseline_summary = self._rolling_stats(BeamRenderMode.BASELINE_SPRITE, self._scenario_preset).summary()
        for mode in _RENDER_MODE_ORDER:
            summary = self._rolling_stats(mode, self._scenario_preset).summary()
            if summary is None:
                line = f"{_mode_label(mode):>8} n=0"
            else:
                if mode == BeamRenderMode.BASELINE_SPRITE:
                    delta_calls = "ref"
                    delta_ms = "ref"
                else:
                    calls_delta_val = None if baseline_summary is None else self._delta_percent(
                        summary.avg_draw_calls_total,
                        baseline_summary.avg_draw_calls_total,
                    )
                    ms_delta_val = None if baseline_summary is None else self._delta_percent(
                        summary.avg_beam_draw_ms,
                        baseline_summary.avg_beam_draw_ms,
                    )
                    delta_calls = "n/a" if calls_delta_val is None else f"{calls_delta_val:+.1f}%"
                    delta_ms = "n/a" if ms_delta_val is None else f"{ms_delta_val:+.1f}%"

                line = (
                    f"{_mode_label(mode):>8} n={summary.sample_count} "
                    f"calls a/p50/p95={summary.avg_draw_calls_total:.1f}/{summary.p50_draw_calls_total:.1f}/{summary.p95_draw_calls_total:.1f} "
                    f"beam_ms a/p50/p95={summary.avg_beam_draw_ms:.3f}/{summary.p50_beam_draw_ms:.3f}/{summary.p95_beam_draw_ms:.3f} "
                    f"frame_ms a/p50/p95={summary.avg_frame_ms:.3f}/{summary.p50_frame_ms:.3f}/{summary.p95_frame_ms:.3f} "
                    f"d_calls={delta_calls} d_ms={delta_ms}"
                )
            draw_ui_text(self._small, line, Vec2(margin, y), color=UI_HINT, scale=0.8)
            y += line_h

        plan = selected.plan
        start = 0.0 if plan is None else float(plan.start)
        span = 0.0 if plan is None else float(plan.span)
        segment_count = 0 if plan is None else int(plan.count)
        draw_ui_text(
            self._small,
            (
                f"selected idx={selected.index} dist={selected.dist_units:.3f} life={selected.life:.3f} "
                f"start={start:.3f} span={span:.3f} raw_segments={segment_count}"
            ),
            Vec2(margin, y),
            color=UI_TEXT,
            scale=0.8,
        )

        if self._missing_assets:
            y += line_h
            draw_ui_text(
                self._small,
                "missing assets: " + ", ".join(sorted(self._missing_assets)),
                Vec2(margin, y),
                color=OVERLAY_MARK,
                scale=0.8,
            )

    def draw(self) -> None:
        frame_start = time.perf_counter()

        if self._shader_fit_requested:
            self._run_shader_profile_autofit()

        rl.clear_background(BG)
        self._draw_grid()

        previews = self._build_previews()
        if not previews:
            return

        if self._bench_active:
            self._render_mode = _RENDER_MODE_ORDER[self._benchmark_mode_index()]

        selected = self._selected_preview(previews)
        side_by_side = bool(self._side_by_side_enabled and not self._bench_active)

        baseline_panel_result: BeamRenderFrameResult | None = None
        baseline_panel_beam_draw_ms: float | None = None
        geometry_sets: list[tuple[Sequence[_PreviewProjectile], _PreviewProjectile]] = [(previews, selected)]

        if side_by_side:
            half_shift = float(rl.get_screen_width()) * 0.25
            left_previews = self._translate_previews(previews, dx=-half_shift)
            right_previews = self._translate_previews(previews, dx=half_shift)
            left_selected = self._selected_preview(left_previews)
            right_selected = self._selected_preview(right_previews)
            geometry_sets = [(left_previews, left_selected), (right_previews, right_selected)]

            self._draw_compare_divider()

            left_start = time.perf_counter()
            baseline_panel_result, _ = self._draw_projectiles(left_previews, mode=BeamRenderMode.BASELINE_SPRITE)
            baseline_panel_beam_draw_ms = (time.perf_counter() - left_start) * 1000.0

            right_start = time.perf_counter()
            render_result, fallback = self._draw_projectiles(right_previews, mode=self._render_mode)
            beam_draw_ms = (time.perf_counter() - right_start) * 1000.0
            self._last_shader_fallback = bool(fallback)
        else:
            beam_start = time.perf_counter()
            render_result, fallback = self._draw_projectiles(previews, mode=self._render_mode)
            beam_draw_ms = (time.perf_counter() - beam_start) * 1000.0
            self._last_shader_fallback = bool(fallback)

        run_batch_probe = bool(self._batch_probe_auto or self._batch_probe_run_once)
        if run_batch_probe:
            self._batch_probe_last = self._run_batch_probe()
            self._batch_probe_run_once = False

        if self._show_geometry_overlay:
            for panel_previews, panel_selected in geometry_sets:
                for preview in panel_previews:
                    self._draw_projectile_geometry(preview, selected=(preview.index == panel_selected.index))

            if self._show_all_segment_markers:
                for panel_previews, _ in geometry_sets:
                    for preview in panel_previews:
                        self._draw_segment_markers(preview)
            else:
                for _, panel_selected in geometry_sets:
                    self._draw_segment_markers(panel_selected)

        self._draw_overlay(
            previews,
            selected,
            render_result=render_result,
            beam_draw_ms=beam_draw_ms,
            baseline_panel_result=baseline_panel_result,
            baseline_panel_beam_draw_ms=baseline_panel_beam_draw_ms,
        )

        frame_ms = (time.perf_counter() - frame_start) * 1000.0
        frame_stats = BeamFrameStats(
            beam_draw_calls_total=int(render_result.current_counts.total_calls),
            beam_draw_calls_body=int(render_result.current_counts.body_calls),
            beam_draw_calls_head=int(render_result.current_counts.head_calls),
            beam_draw_calls_overlay=int(render_result.current_counts.overlay_calls),
            beam_draw_ms=float(beam_draw_ms),
            frame_ms=float(frame_ms),
        )
        if side_by_side and baseline_panel_result is not None and baseline_panel_beam_draw_ms is not None:
            baseline_stats = BeamFrameStats(
                beam_draw_calls_total=int(baseline_panel_result.current_counts.total_calls),
                beam_draw_calls_body=int(baseline_panel_result.current_counts.body_calls),
                beam_draw_calls_head=int(baseline_panel_result.current_counts.head_calls),
                beam_draw_calls_overlay=int(baseline_panel_result.current_counts.overlay_calls),
                beam_draw_ms=float(baseline_panel_beam_draw_ms),
                frame_ms=float(frame_ms),
            )
            self._rolling_stats(BeamRenderMode.BASELINE_SPRITE, self._scenario_preset).add(baseline_stats)
            if self._render_mode != BeamRenderMode.BASELINE_SPRITE:
                self._rolling_stats(self._render_mode, self._scenario_preset).add(frame_stats)
            self._last_frame_stats = frame_stats
        else:
            self._record_frame_stats(frame_stats)
        self._last_render_result = render_result
        self._advance_benchmark_after_frame()


@register_view("beam-debug", "Beam render debug")
def build_beam_debug_view(ctx: ViewContext) -> View:
    return BeamDebugView(ctx)


__all__ = [
    "BatchProbeResult",
    "BeamCountInput",
    "BeamDrawCounts",
    "BeamFrameStats",
    "BeamModeRollingStats",
    "BeamRenderMode",
    "BeamScenarioConfig",
    "BeamScenarioPreset",
    "BeamStatsSummary",
    "BeamDebugView",
    "beam_scenario_config",
    "cycle_beam_render_mode",
    "estimate_beam_frame_counts",
    "resolve_beam_debug_assets_root",
]
