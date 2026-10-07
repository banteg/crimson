from __future__ import annotations

import io
from pathlib import Path

import pytest
from PIL import Image

from crimson.render.world.context import draw_late_bullet_pass_sprite
from grim.assets import _load_texture_asset_from_bytes, load_paq_entries
from grim.geom import Vec2
from grim.raylib_api import rl


def _quarter_texture(*, top_right_opaque: bool) -> rl.Texture:
    # 16x16 like bullet16.tga: white where opaque, only the top-right quarter differs.
    image = rl.gen_image_color(16, 16, rl.Color(0, 0, 0, 0) if top_right_opaque else rl.WHITE)
    rl.image_draw_rectangle(image, 12, 0, 4, 4, rl.WHITE if top_right_opaque else rl.Color(0, 0, 0, 0))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    return texture


def _lit_pixels(texture: rl.Texture) -> int:
    target = rl.load_render_texture(32, 32)
    try:
        rl.begin_texture_mode(target)
        rl.clear_background(rl.BLACK)
        draw_late_bullet_pass_sprite(texture, screen_pos=Vec2(16.0, 16.0), size=24.0, angle=0.0, alpha=1.0)
        rl.end_texture_mode()
        image = rl.load_image_from_texture(target.texture)
        try:
            return sum(1 for x in range(32) for y in range(32) if rl.get_image_color(image, x, y).r > 16)
        finally:
            rl.unload_image(image)
    finally:
        rl.unload_render_texture(target)


@pytest.mark.parametrize(("top_right_opaque", "visible"), [(False, False), (True, True)])
def test_late_bullet_pass_samples_only_the_top_right_quarter(
    raylib_context, top_right_opaque: bool, visible: bool,
) -> None:
    # Native leaves effect 13's UVs bound, so the pass reads just this corner,
    # which is transparent in bullet16 and hides every head and plasma core.
    texture = _quarter_texture(top_right_opaque=top_right_opaque)
    try:
        assert (_lit_pixels(texture) > 0) is visible
    finally:
        rl.unload_texture(texture)


def test_original_bullet_texture_keeps_late_heads_invisible(raylib_context, assets_dir: Path) -> None:
    data = load_paq_entries(assets_dir)["load/bullet16.tga"]
    image = Image.open(io.BytesIO(data)).convert("RGBA")
    assert image.size == (16, 16)
    assert image.getchannel("A").getextrema() == (0, 255)
    assert image.crop((12, 0, 16, 4)).getchannel("A").getextrema() == (0, 0)
    texture = _load_texture_asset_from_bytes("load/bullet16.tga", data)
    assert texture is not None
    try:
        assert _lit_pixels(texture) == 0
    finally:
        rl.unload_texture(texture)
