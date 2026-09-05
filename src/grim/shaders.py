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
        rl.begin_shader_mode(self.shader)
        try:
            yield
        finally:
            rl.end_shader_mode()

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
            self.shader = None
