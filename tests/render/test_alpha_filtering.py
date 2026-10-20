from __future__ import annotations

import pytest

from crimson.render.rtx.bonus_shaders import BONUS_FRAGMENT
from crimson.render.rtx.creature_shaders import CREATURE_FRAGMENT, CREATURE_VERTEX
from grim.blend import opaque_blend
from grim.raylib_api import rl
from grim.shaders import _ALPHA_TEST_FS_330, _ALPHA_TEST_VS_330
from grim.texture_mode import texture_mode


@pytest.mark.parametrize("fragment", [
    _ALPHA_TEST_FS_330,
    _ALPHA_TEST_FS_330.replace("alphaBilinear(texture0", "alphaCatmullRom(texture0"),
    CREATURE_FRAGMENT,
    BONUS_FRAGMENT,
], ids=["world", "terrain", "creature", "bonus"])
def test_transparent_rgb_cannot_contaminate_visible_edges(raylib_context, fragment: str) -> None:
    # Creature/bonus shaders need their world-coordinate vertex output.
    vertex = CREATURE_VERTEX if fragment in (CREATURE_FRAGMENT, BONUS_FRAGMENT) else _ALPHA_TEST_VS_330
    shader = rl.load_shader_from_memory(vertex, fragment)
    assert shader.id > 0 and shader.id != rl.rl_get_shader_id_default()
    for name in ("u_view_scale", "u_grid"):
        loc = rl.get_shader_location(shader, name)
        if loc >= 0:
            rl.set_shader_value(shader, loc, rl.ffi.new("float[2]", [1., 1.]),
                                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2)
    loc = rl.get_shader_location(shader, "u_pass")
    if loc >= 0:
        rl.set_shader_value(shader, loc, rl.ffi.new("int *", 1), rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
    target = rl.load_render_texture(16, 8)
    outputs = []
    try:
        for hidden_rgb in (rl.Color(0, 0, 0, 0), rl.Color(0, 0, 255, 0)):
            image = rl.gen_image_color(2, 1, hidden_rgb)
            rl.image_draw_pixel(image, 0, 0, rl.Color(255, 0, 0, 255))
            texture = rl.load_texture_from_image(image)
            rl.unload_image(image)
            rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
            rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
            with texture_mode(target), opaque_blend():
                rl.clear_background(rl.BLANK)
                rl.begin_shader_mode(shader)
                rl.draw_texture_pro(texture, rl.Rectangle(0, 0, 2, 1), rl.Rectangle(0, 0, 16, 8),
                                    rl.Vector2(), 0., rl.WHITE)
                rl.end_shader_mode()
            result = rl.load_image_from_texture(target.texture)
            outputs.append([(c.r, c.g, c.b, c.a) for x in range(16)
                            for c in [rl.get_image_color(result, x, 4)]])
            rl.unload_image(result)
            rl.unload_texture(texture)
        assert outputs[0] == outputs[1]
        # Smooth coverage survives, while red retains its original unassociated color.
        edge = outputs[0][7]
        assert edge[:3] == (255, 0, 0)
        assert 100 < edge[3] < 180
    finally:
        rl.unload_shader(shader)
        rl.unload_render_texture(target)
