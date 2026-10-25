from __future__ import annotations

import struct

import pytest

from crimson.render.rtx.materials import _shader, _uniform
from crimson.render.rtx.shaders import glsl
from grim.edr import load_float_render_texture
from grim.raylib_api import rl
from grim.texture_mode import texture_mode

WIDTH = 64


def _ramp(headroom: float, low: float, high: float) -> list[tuple[float, float, float]]:
    """The tonemap of a warm color ramped from peak `low` to `high` across one row of a 32-bit float target."""
    source = glsl("hdr_tonemap.frag").replace("void main()", "void tonemap_main()")
    shader = _shader(source + f"""
    uniform vec4 u_ramp;
    void main() {{
        float peak = u_ramp.y + (gl_FragCoord.x - 0.5) / {WIDTH}. * (u_ramp.z - u_ramp.y);
        finalColor = vec4(tonemap_hue_preserving(vec3(peak, 0.45 * peak, 0.12 * peak), u_ramp.x), 1.);
    }}
    """)
    target = load_float_render_texture(WIDTH, 1, pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
    try:
        _uniform(shader, "u_ramp", [headroom, low, high, 0.0])
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.draw_rectangle(0, 0, WIDTH, 1, rl.WHITE)
            rl.end_shader_mode()
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            values = struct.unpack(f"{WIDTH * 4}f", bytes(rl.ffi.buffer(image.data, WIDTH * 16)))
        finally:
            rl.unload_image(image)
    finally:
        rl.unload_shader(shader)
        rl.unload_render_texture(target)
    return [values[i * 4:i * 4 + 3] for i in range(WIDTH)]


def _slope(xs: list[float], ys: list[float]) -> float:
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / sum((x - mx) ** 2 for x in xs)


@pytest.mark.parametrize("headroom", [1.0, 4.0])
@pytest.mark.parametrize("peak", [1.0, 2.5, 4.0])
def test_tonemap_slope_is_continuous_where_highlights_whiten(raylib_context, headroom, peak) -> None:
    # A slope break is a visible contour (a Mach band) wherever a glow's brightness passes through it. Across a narrow
    # window, smooth curvature changes the slope a little while a break keeps its whole jump.
    half = 0.005
    rows = _ramp(headroom, peak - half, peak + half)
    xs = [peak - half + (i + 0.5) / WIDTH * 2 * half for i in range(WIDTH)]
    left, right = slice(0, WIDTH * 3 // 8), slice(WIDTH * 5 // 8, WIDTH)
    for channel in range(3):
        ys = [row[channel] for row in rows]
        jump = abs(_slope(xs[right], ys[right]) - _slope(xs[left], ys[left]))
        assert jump < 0.03, (channel, jump)
