from __future__ import annotations

import pytest
from PIL import Image

from crimson.render.rtx import creature_lighting
from crimson.render.rtx.creature_lighting import CreatureLighting
from crimson.render.rtx.creature_translucency import blur_cells, build_thickness_proxy
from crimson.render.rtx.material_lights import MaterialLight
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.texture_mode import texture_mode


def test_part_size_keeps_torso_boundaries_thick_and_limbs_thin() -> None:
    alpha = Image.new("L", (512, 512))
    alpha.paste(255, (0, 0, 64, 64))
    # An isolated three-texel-wide limb in another animation cell.
    alpha.paste(255, (80, 8, 83, 40))
    thickness = build_thickness_proxy(alpha)
    assert thickness.mode == "L" and thickness.size == alpha.size
    assert thickness.getpixel((0, 32)) == 255
    assert thickness.getpixel((3, 32)) == 255
    assert thickness.getpixel((31, 31)) == 255
    assert thickness.getpixel((80, 20)) == 32
    assert thickness.getpixel((81, 20)) == 32
    assert thickness.getpixel((79, 20)) == 0
    assert thickness.getpixel((100, 100)) == 0


def test_touching_atlas_frames_are_separate_solids() -> None:
    alpha = Image.new("L", (256, 256))
    alpha.paste(255, (0, 0, 32, 32))
    isolated = build_thickness_proxy(alpha)
    alpha.paste(255, (32, 0, 64, 64))
    alpha.paste(255, (0, 32, 32, 64))
    surrounded = build_thickness_proxy(alpha)
    assert isolated.crop((0, 0, 32, 32)).tobytes() == surrounded.crop((0, 0, 32, 32)).tobytes()
    assert surrounded.getpixel((31, 16)) == surrounded.getpixel((32, 16)) == 255
    assert surrounded.getpixel((16, 31)) == surrounded.getpixel((16, 32)) == 255


def test_thick_body_does_not_reconstruct_a_connected_thin_appendage() -> None:
    alpha = Image.new("L", (512, 512))
    alpha.paste(255, (4, 8, 32, 40))
    alpha.paste(255, (32, 22, 56, 25))
    thickness = build_thickness_proxy(alpha)
    assert thickness.getpixel((4, 23)) == 14 * 16
    assert thickness.getpixel((30, 20)) == 14 * 16
    # Every point across the distant limb, including its side edges, has the
    # same narrow support. Reconstructing a torso cannot flood an attached leg.
    assert [thickness.getpixel((45, y)) for y in range(22, 25)] == [32] * 3
    assert thickness.getpixel((45, 21)) == 0


@pytest.mark.parametrize("size", [(8, 8), (16, 24), (40, 56)])
def test_opening_matches_contained_square_support(size: tuple[int, int]) -> None:
    # Independent geometric oracle: enumerate squares and stamp the largest
    # covering radius. Tiny random cells expose offset wrap and adjacent leakage.
    import random

    rng = random.Random(810)
    alpha = Image.frombytes("L", size, bytes(rng.choice((0, 3, 4, 255, 255, 255)) for _ in range(size[0]*size[1])))
    expected = Image.new("L", size)
    cell_width, cell_height = size[0] // 8, size[1] // 8
    for cy in range(8):
        for cx in range(8):
            x0, y0 = cx * cell_width, cy * cell_height
            for radius in range(16):
                width = 2 * radius + 1
                for y in range(y0, y0 + cell_height - width + 1):
                    for x in range(x0, x0 + cell_width - width + 1):
                        box = (x, y, x + width, y + width)
                        if min(alpha.crop(box).tobytes()) >= 4:
                            expected.paste(min(255, 16 * (radius + 1)), box)
    assert build_thickness_proxy(alpha).tobytes() == expected.tobytes()


def test_thickness_uses_native_alpha_cutoff() -> None:
    alpha = Image.new("L", (64, 64), 3)
    alpha.putpixel((3, 3), 4)
    alpha.putpixel((4, 3), 255)
    thickness = build_thickness_proxy(alpha)
    assert thickness.getpixel((2, 3)) == 0
    assert thickness.getpixel((3, 3)) == thickness.getpixel((4, 3)) == 16
    assert sum(value != 0 for value in thickness.tobytes()) == 2


@pytest.mark.parametrize("size", [(63, 64), (64, 65), (7, 8)])
def test_thickness_rejects_incomplete_atlas_cells(size: tuple[int, int]) -> None:
    with pytest.raises(ValueError):
        build_thickness_proxy(Image.new("L", size))


def test_consecutive_species_bind_their_own_cached_thickness(raylib_context, mocker) -> None:
    thick_image = rl.gen_image_color(256, 256, rl.BLANK)
    thin_image = rl.gen_image_color(256, 256, rl.BLANK)
    color = rl.Color(70, 55, 40, 255)
    rl.image_draw_rectangle(thick_image, 0, 0, 32, 32, color)
    rl.image_draw_rectangle(thin_image, 0, 15, 32, 3, color)
    thick = rl.load_texture_from_image(thick_image)
    thin = rl.load_texture_from_image(thin_image)
    rl.unload_image(thick_image)
    rl.unload_image(thin_image)
    target = rl.load_render_texture(64, 64)
    lighting = CreatureLighting()
    load = mocker.spy(creature_lighting, "load_thickness_texture")
    lights = [MaterialLight(Vec2(6, 32), 110, (1.4, .68, .2), height=40)]

    def render(texture):
        lighting.prepare(lights, camera=Vec2(), view_scale=Vec2(1, 1))
        with texture_mode(target):
            rl.clear_background(rl.BLANK)
            with lighting.scope(texture=texture, restore_shader=None):
                rl.draw_texture_pro(
                    texture, rl_rectangle(0, 0, 32, 32), rl_rectangle(32, 32, 32, 32),
                    rl_vector2(16, 16), 0, rl.WHITE,
                )
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
            return bytes(rl.ffi.buffer(image.data, 64 * 64 * 4))
        finally:
            rl.unload_image(image)

    try:
        first_thick = render(thick)
        first_thin = render(thin)
        assert render(thick) == first_thick
        assert render(thin) == first_thin
        assert load.call_count == 2
        assert set(lighting.thickness_textures) == {thick.id, thin.id}
        lighting.close()
        assert not lighting.thickness_textures
        # A new shader/cache must agree with the image after a different atlas was bound.
        assert render(thin) == first_thin
        assert render(thick) == first_thick
        assert load.call_count == 4
    finally:
        lighting.close()
        rl.unload_texture(thick)
        rl.unload_texture(thin)
        rl.unload_render_texture(target)


def test_cell_blur_softens_within_a_cell_and_never_bleeds_across() -> None:
    proxy = Image.new("L", (64, 64))
    proxy.paste(255, (0, 0, 8, 8))  # one full cell next to empty ones
    proxy.paste(160, (12, 12, 13, 13))  # a lone texel inside the next cell
    blurred = blur_cells(proxy, 2)
    assert blurred.getpixel((7, 4)) == 255  # extended edges keep a full cell full
    assert blurred.getpixel((8, 4)) == blurred.getpixel((4, 8)) == 0
    assert blurred.getpixel((12, 12)) == round(160 / 25)
    assert blurred.getpixel((14, 14)) == round(160 / 25)
    assert blurred.getpixel((15, 15)) == 0
