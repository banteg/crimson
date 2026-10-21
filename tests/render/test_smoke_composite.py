from __future__ import annotations

import numpy as np
import pytest

from crimson.render.rtx.smoke_composite import SmokeComposite, smoke_target_size
from crimson.render.rtx.smoke_shaders import SMOKE_VERTEX
from crimson.render.world.viewport import ViewTransform
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode


@pytest.mark.parametrize(("size", "expected"), [
    ((2048, 1536), (640, 480)), ((1024, 768), (640, 480)),
    ((320, 240), (320, 240)), ((600, 1200), (320, 640)),
])
def test_smoke_target_caps_physical_dimensions(size, expected):
    assert smoke_target_size(*size) == expected


def test_native_smoke_composite_preserves_hdr_alpha_orientation_and_nested_scale(raylib_context):
    # Half-transparent HDR panes exercise premultiplication, not merely opaque
    # color. Two logical scales exercise restoration of the outer target matrix.
    fragment = """#version 330
in vec2 fragTexCoord;
out vec4 finalColor;
void main() {
    finalColor=fragTexCoord.y<.5 ? vec4(4.,.5,.1,.25) : vec4(.1,.5,3.,.75);
}
"""
    shader = rl.load_shader_from_memory(SMOKE_VERTEX, fragment)
    assert shader.id != rl.rl_get_shader_id_default()
    target = load_float_render_texture(128, 96)
    image = rl.gen_image_color(2, 2, rl.WHITE)
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    composite = SmokeComposite()

    def pixels():
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            return np.frombuffer(rl.ffi.buffer(image.data, 128 * 96 * 16), dtype=np.float32).copy().reshape(96, 128, 4)
        finally:
            rl.unload_image(image)

    try:
        for logical_scale in (1., 2.):
            out = Vec2(128 / logical_scale, 96 / logical_scale)
            view = ViewTransform(Vec2(), Vec2(1, 1), out, out)

            def pane(out=out):
                rl.begin_shader_mode(shader)
                rl.draw_texture_pro(texture, rl.Rectangle(0, 0, 2, 2), rl.Rectangle(0, 0, out.x, out.y), rl.Vector2(0, 0), 0, rl.WHITE)
                rl.end_shader_mode()

            with texture_mode(target, scale_x=logical_scale, scale_y=logical_scale):
                rl.clear_background(rl.Color(51, 51, 51, 255))
                pane()
            direct = pixels()
            with texture_mode(target, scale_x=logical_scale, scale_y=logical_scale):
                rl.clear_background(rl.Color(51, 51, 51, 255))
                composite.draw(view, pane)
            reduced = pixels()
            assert float(reduced[:, :, :3].max()) > 1.
            np.testing.assert_allclose(reduced[:, :, :3], direct[:, :, :3], atol=.002)
            assert composite.target is not None
            assert (composite.target.texture.width, composite.target.texture.height) == (128, 96)
    finally:
        composite.close()
        composite.close()
        rl.unload_texture(texture)
        rl.unload_shader(shader)
        rl.unload_render_texture(target)
