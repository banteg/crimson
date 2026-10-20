from __future__ import annotations

import struct

import pytest

from crimson.render.rtx.bonus_shaders import BONUS_FRAGMENT
from crimson.render.rtx.creature_shaders import CREATURE_FRAGMENT, CREATURE_VERTEX
from crimson.render.rtx.material_shaders import STAMP_FRAGMENT
from grim.blend import opaque_blend
from grim.raylib_api import rl
from grim.shaders import _ALPHA_TEST_FS_330, _PIXEL_COVERAGE_FS_330
from grim.texture_mode import texture_mode


@pytest.mark.parametrize("fragment", [_ALPHA_TEST_FS_330, _PIXEL_COVERAGE_FS_330, CREATURE_FRAGMENT, STAMP_FRAGMENT,
                                     BONUS_FRAGMENT],
                         ids=["world", "font", "creature", "material", "bonus"])
@pytest.mark.parametrize(("source_alpha", "tint_alpha", "passes"), [
    (0.0, 255, False),
    (3.0, 255, False),
    (3.49, 255, False),
    (3.5, 255, True),
    (3.51, 255, True),
    (4.0, 255, True),
    (7.0, 127, False),
    (7.0, 128, True),
    (255.0, 3, False),
    (255.0, 4, True),
])
def test_bitmap_alpha_test_uses_modulated_byte_alpha(
    raylib_context, fragment: str, source_alpha: float, tint_alpha: int, passes: bool,
) -> None:
    # Native grim_apply_render_state @ 0x10004520 sets ALPHAFUNC=7 (>=), ALPHAREF=4.
    # Fractional alpha follows the byte conversion in crimson-core/client/renderer.cpp.
    # Float texture input isolates the boundary from UNORM texture-upload quantization.
    data = rl.ffi.new("char[]", struct.pack("4f", 1., 1., 1., source_alpha / 255))
    image = rl.ffi.new("Image *", {
        "data": data, "width": 1, "height": 1, "mipmaps": 1,
        "format": rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32,
    })
    texture = rl.load_texture_from_image(image[0])
    shader = rl.load_shader_from_memory(CREATURE_VERTEX, fragment)
    target = rl.load_render_texture(16, 16)
    try:
        assert shader.id != rl.rl_get_shader_id_default()
        for name, value in (("alphaCutoff", 4.), ("cellSize", 1.)):
            loc = rl.get_shader_location(shader, name)
            if loc >= 0:
                rl.set_shader_value(shader, loc, rl.ffi.new("float *", value),
                                    rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT)
        for name in ("u_view_scale", "u_grid"):
            loc = rl.get_shader_location(shader, name)
            if loc >= 0:
                rl.set_shader_value(shader, loc, rl.ffi.new("float[2]", [1., 1.]),
                                    rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2)
        for name in ("u_kind", "u_pass"):
            loc = rl.get_shader_location(shader, name)
            if loc >= 0:
                value = int(name == "u_kind" or fragment == BONUS_FRAGMENT)
                rl.set_shader_value(shader, loc, rl.ffi.new("int *", value),
                                    rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
        with texture_mode(target), opaque_blend():
            rl.clear_background(rl.BLUE)
            rl.begin_shader_mode(shader)
            try:
                rl.draw_texture_pro(texture, rl.Rectangle(0, 0, 1, 1), rl.Rectangle(0, 0, 16, 16),
                                    rl.Vector2(), 0., rl.Color(255, 255, 255, tint_alpha))
            finally:
                rl.end_shader_mode()
        result = rl.load_image_from_texture(target.texture)
        try:
            assert rl.get_image_color(result, 8, 8).r == (255 if passes else 0)
        finally:
            rl.unload_image(result)
    finally:
        rl.unload_render_texture(target)
        rl.unload_shader(shader)
        rl.unload_texture(texture)
