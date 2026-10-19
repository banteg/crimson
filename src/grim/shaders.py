from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import msgspec

from .raylib_api import rl

# Grim2D enables alpha test globally with:
#   ALPHATESTENABLE=1, ALPHAFUNC=GREATER, ALPHAREF=4
# Static anchor: `grim_apply_render_state` @ 0x10004520.
#
# raylib does not expose fixed-function alpha test, so we emulate it with a tiny
# discard shader for world drawing and terrain stamps. This shim is
# required for parity; if it fails to compile, rendering should stop rather than
# silently drift away from the native cutoff behavior.
_ALPHA_TEST_VS_330 = r"""
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

_ALPHA_TEST_FS_330 = r"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;

out vec4 finalColor;

void main() {
    // Emulate DX8 fixed-function alpha test after stage-0 modulation:
    // stage output = texture * diffuse, then discard when alpha <= 4/255.
    vec4 texel = texture(texture0, fragTexCoord) * fragColor * colDiffuse;
    if (texel.a <= 4.0 / 255.0) discard;
    finalColor = texel;
}
"""


# Raylib's EndShaderMode resets to the default shader, not the enclosing one.
# Bonus hover text runs inside the world's alpha-test scope.
_shader_stack: list[tuple[rl.Shader, bool]] = []


@contextmanager
def _shader_scope(shader: rl.Shader, *, alpha_test: bool) -> Iterator[None]:
    rl.begin_shader_mode(shader)
    _shader_stack.append((shader, alpha_test))
    try:
        yield
    finally:
        _shader_stack.pop()
        if _shader_stack:
            rl.begin_shader_mode(_shader_stack[-1][0])
        else:
            rl.end_shader_mode()


class AlphaTestShader(msgspec.Struct):
    """Lazily loaded alpha-test shader owned by a graphics resource lifetime."""

    shader: rl.Shader | None = None

    @contextmanager
    def scope(self) -> Iterator[None]:
        if self.shader is None:
            shader = rl.load_shader_from_memory(_ALPHA_TEST_VS_330, _ALPHA_TEST_FS_330)
            if shader.id <= 0:
                raise RuntimeError("alpha-test shader compilation returned an invalid shader id")
            self.shader = shader
        with _shader_scope(self.shader, alpha_test=True):
            yield

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
            self.shader = None


# Pixel-area coverage for magnified, axis-aligned bitmap text. This is the
# sharpness=1, no-subpixel-AA sampling in Pixel AA (fishku, CC0):
# https://github.com/libretro/glsl-shaders/blob/master/pixel-art-scaling/shaders/pixel_aa/pixel_aa.glsl
# Keep the game's straight-alpha blending and tint, without a gamma transform.
_PIXEL_COVERAGE_FS_330 = r"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform float alphaCutoff;

out vec4 finalColor;

void main() {
    vec2 size = vec2(textureSize(texture0, 0));
    vec2 texel = fragTexCoord * size;
    // Derivatives include canvas and DPI scaling, including nested targets.
    vec2 footprint = max(fwidth(texel), vec2(0.00001));
    vec2 p = texel - 0.5;
    // Bilinear sampling only crosses a texel edge over one output pixel.
    vec2 blend = clamp((fract(p) - 0.5) / footprint + 0.5, 0.0, 1.0);
    vec2 uv = (floor(p) + 0.5 + blend) / size;
    vec4 texelColor = texture(texture0, uv) * fragColor * colDiffuse;
    if (texelColor.a <= alphaCutoff) discard;
    finalColor = texelColor;
}
"""


class PixelCoverageShader(msgspec.Struct):
    """Small-font sampler; the atlas must use bilinear texture filtering."""

    shader: rl.Shader | None = None
    _alpha_cutoff_loc: int = -1

    @contextmanager
    def scope(self) -> Iterator[None]:
        if self.shader is None:
            shader = rl.load_shader_from_memory(_ALPHA_TEST_VS_330, _PIXEL_COVERAGE_FS_330)
            # Raylib returns the default shader when compilation/linking fails.
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("pixel-coverage shader compilation failed")
            self.shader = shader
            self._alpha_cutoff_loc = rl.get_shader_location(shader, "alphaCutoff")
        alpha_test = bool(_shader_stack and _shader_stack[-1][1])
        with _shader_scope(self.shader, alpha_test=alpha_test):
            rl.set_shader_value(
                self.shader, self._alpha_cutoff_loc,
                rl.ffi.new("float *", 4.0 / 255.0 if alpha_test else -1.0),
                rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
            )
            yield

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
            self.shader = None
        self._alpha_cutoff_loc = -1
