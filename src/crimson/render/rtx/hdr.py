from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import msgspec

from grim.blend import opaque_blend
from grim.edr import HDR_PIXEL_FORMAT, load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.texture_mode import current_target_edr_headroom, current_target_size, texture_mode

HDR_SHOULDER_KNEE = 0.85
HDR_WHITE_DRIFT = 0.6
HDR_WHITE_SPAN = 3.0

_HDR_TONEMAP_VS_330 = r"""
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;

out vec2 fragTexCoord;
out vec4 fragColor;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

_HDR_TONEMAP_FS_330 = f"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform float u_edr_headroom;

out vec4 finalColor;

const float KNEE = {HDR_SHOULDER_KNEE:.6f};
const float WHITE_DRIFT = {HDR_WHITE_DRIFT:.6f};
const float WHITE_SPAN = {HDR_WHITE_SPAN:.6f};

float shoulder_to(float x, float knee, float limit) {{
    float span = max(limit - knee, 1e-4);
    return (x <= knee) ? x : (knee + span * (1.0 - exp(-(x - knee) / span)));
}}

vec3 tonemap_hue_preserving(vec3 rgb, float headroom) {{
    vec3 x = max(rgb, vec3(0.0));
    float peak = max(x.r, max(x.g, x.b));
    if (peak <= KNEE) {{
        return x;
    }}
    // NSScreen headroom is linear; this legacy OpenGL pipeline is approximately
    // gamma-2.2 encoded. This is a display-relative limit, not a nit calibration.
    // The same shoulder works continuously down to headroom=1 (SDR).
    float limit = pow(max(headroom, 1.0), 1.0 / 2.2);
    float mapped = shoulder_to(peak, KNEE, limit);
    vec3 out_rgb = x * (mapped / max(peak, 1e-6));
    float heat = clamp((peak - 1.0) / WHITE_SPAN, 0.0, 1.0) * WHITE_DRIFT;
    return mix(out_rgb, vec3(mapped), heat);
}}

void main() {{
    vec4 texel = texture(texture0, fragTexCoord);
    float headroom = max(u_edr_headroom, 1.0);
    vec3 mapped = tonemap_hue_preserving(texel.rgb, headroom) * fragColor.rgb * colDiffuse.rgb;
    finalColor = vec4(mapped, 1.0);
}}
"""

load_float_target = load_float_render_texture


class HdrRenderer(msgspec.Struct):
    """Lazily allocated RGBA16F world target and EDR/SDR hue-preserving tonemapper for RTX mode."""

    target: rl.RenderTexture | None = None
    shader: rl.Shader | None = None
    headroom_loc: int = -1

    def _ensure_resources(self, width: int, height: int) -> tuple[rl.RenderTexture, rl.Shader]:
        if self.shader is None:
            shader = rl.load_shader_from_memory(_HDR_TONEMAP_VS_330, _HDR_TONEMAP_FS_330)
            if int(shader.id) <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("hdr tonemap shader compilation returned an invalid shader id")
            headroom_loc = int(rl.get_shader_location(shader, "u_edr_headroom"))
            if headroom_loc < 0:
                rl.unload_shader(shader)
                raise RuntimeError("hdr tonemap shader is missing its headroom uniform")
            self.shader = shader
            self.headroom_loc = headroom_loc
        target = self.target
        if target is None or int(target.texture.width) != int(width) or int(target.texture.height) != int(height):
            candidate = load_float_render_texture(width, height)
            if target is not None:
                rl.unload_render_texture(target)
            self.target = candidate
            target = candidate
        return target, self.shader

    @contextmanager
    def scope(self, *, out_size: Vec2) -> Iterator[None]:
        out_w = float(out_size.x)
        out_h = float(out_size.y)
        render_w, render_h = current_target_size()
        headroom = float(current_target_edr_headroom())
        if min(out_w, out_h, render_w, render_h) <= 0:
            yield
            return
        target, shader = self._ensure_resources(render_w, render_h)
        with texture_mode(target, scale_x=render_w / out_w, scale_y=render_h / out_h):
            rl.clear_background(rl.BLACK)
            yield
        if self.headroom_loc >= 0:
            rl.set_shader_value(
                shader,
                self.headroom_loc,
                rl.ffi.new("float *", headroom),
                rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
            )
        rl.begin_shader_mode(shader)
        try:
            with opaque_blend():
                rl.draw_texture_pro(
                    target.texture,
                    rl_rectangle(0.0, 0.0, float(render_w), -float(render_h)),
                    rl_rectangle(0.0, 0.0, out_w, out_h),
                    rl_vector2(0.0, 0.0),
                    0.0,
                    rl.WHITE,
                )
        finally:
            rl.end_shader_mode()

    def close(self) -> None:
        if self.target is not None:
            rl.unload_render_texture(self.target)
            self.target = None
        if self.shader is not None:
            rl.unload_shader(self.shader)
            self.shader = None
        self.headroom_loc = -1


__all__ = [
    "HDR_PIXEL_FORMAT",
    "HDR_SHOULDER_KNEE",
    "HDR_WHITE_DRIFT",
    "HDR_WHITE_SPAN",
    "HdrRenderer",
    "load_float_target",
]
