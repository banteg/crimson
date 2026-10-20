from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest
from PIL import Image

from grim import assets
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode

# A synthetic glyph with vertical and horizontal one-texel strokes. An area
# integral of these rectangles is an independent reference for GPU coverage.
_INK = ((1, 2, 1, 9), (2, 2, 3, 1), (2, 6, 3, 1), (5, 3, 1, 8))
_BACKGROUND = (15, 20, 30)


@pytest.fixture
def pixel_font(raylib_context) -> Iterator[SmallFontData]:
    image = rl.gen_image_color(256, 256, rl.Color(255, 255, 255, 0))
    for x, y, w, h in _INK:
        rl.image_draw_rectangle(image, 16 + x, 64 + y, w, h, rl.WHITE)
    try:
        texture = rl.load_texture_from_image(image)
    finally:
        rl.unload_image(image)
    rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
    widths = [0] * 256
    widths[ord("A")] = 7
    font = SmallFontData(widths=widths, texture=texture)
    try:
        yield font
    finally:
        font.pixel_coverage.close()
        rl.unload_texture(texture)


def _read_rgb(target: rl.RenderTexture) -> list[tuple[int, int, int]]:
    image = rl.load_image_from_texture(target.texture)
    try:
        rl.image_flip_vertical(image)
        return [
            (color.r, color.g, color.b)
            for y in range(image.height)
            for x in range(image.width)
            for color in (rl.get_image_color(image, x, y),)
        ]
    finally:
        rl.unload_image(image)


@pytest.mark.parametrize("scale", [(1.0, 1.0), (1.25, 1.25), (1.5625, 1.5625), (2.0, 2.0), (3.125, 3.125), (1.5625, 2.0)])
def test_fractional_font_pixels_match_area_coverage_and_tint(pixel_font: SmallFontData, scale: tuple[float, float]) -> None:
    target = rl.load_render_texture(64, 96)
    sx, sy = scale
    tint = (200, 160, 120)
    try:
        with texture_mode(target, scale_x=sx, scale_y=sy):
            rl.clear_background(rl.Color(*_BACKGROUND, 255))
            draw_small_text(pixel_font, "A", Vec2(3.9, 5.9), rl.Color(*tint, 178))
        pixels = _read_rgb(target)
        for y in range(96):
            for x in range(64):
                area = 0.0
                for ix, iy, iw, ih in _INK:
                    left, top = (3 + ix) * sx, (5 + iy) * sy
                    right, bottom = left + iw * sx, top + ih * sy
                    area += max(0.0, min(x + 1, right) - max(x, left)) * max(
                        0.0, min(y + 1, bottom) - max(y, top),
                    )
                alpha = area * 178 / 255
                expected = tuple(round(bg * (1 - alpha) + fg * alpha) for bg, fg in zip(_BACKGROUND, tint, strict=True))
                assert pixels[y * 64 + x] == pytest.approx(expected, abs=2), (scale, x, y)
    finally:
        rl.unload_render_texture(target)


@pytest.mark.parametrize("scale", [1, 2, 3])
def test_aligned_integer_scales_match_nearest(pixel_font: SmallFontData, scale: int) -> None:
    target = rl.load_render_texture(64, 64)
    try:
        with texture_mode(target, scale_x=scale, scale_y=scale):
            rl.clear_background(rl.BLACK)
            draw_small_text(pixel_font, "A", Vec2(3, 5), rl.WHITE)
        actual = _read_rgb(target)
        rl.set_texture_filter(pixel_font.texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
        with texture_mode(target, scale_x=scale, scale_y=scale):
            rl.clear_background(rl.BLACK)
            rl.draw_texture_pro(
                pixel_font.texture, rl_rectangle(16, 64, 7, 16), rl_rectangle(3, 5, 7, 16),
                rl_vector2(0, 0), 0, rl.WHITE,
            )
        assert actual == _read_rgb(target)
    finally:
        rl.unload_render_texture(target)


@pytest.mark.parametrize("alpha", [3, 4])
def test_font_preserves_enclosing_alpha_test_and_restores_default(pixel_font: SmallFontData, alpha: int) -> None:
    target = rl.load_render_texture(64, 32)
    alpha_test = AlphaTestShader()
    try:
        with texture_mode(target):
            rl.clear_background(rl.BLACK)
            with alpha_test.scope():
                draw_small_text(pixel_font, "A", Vec2(0, 0), rl.Color(255, 255, 255, alpha))
                # Drawing text must not disable alpha testing for later world effects.
                rl.draw_rectangle(16, 0, 16, 32, rl.Color(255, 0, 0, alpha))
            draw_small_text(pixel_font, "A", Vec2(32, 0), rl.Color(255, 255, 255, alpha))
            rl.draw_rectangle(48, 0, 16, 32, rl.Color(255, 0, 0, alpha))
        pixels = _read_rgb(target)
        kept = alpha if alpha >= 4 else 0
        assert pixels[4 * 64 + 1] == (kept, kept, kept)
        assert pixels[4 * 64 + 24] == (kept, 0, 0)
        assert pixels[4 * 64 + 33] == (alpha, alpha, alpha)
        assert pixels[4 * 64 + 56] == (alpha, 0, 0)
    finally:
        alpha_test.close()
        rl.unload_render_texture(target)


def test_font_shader_releases_reloads_and_restores_parent_after_error(pixel_font: SmallFontData) -> None:
    alpha_test = AlphaTestShader()
    target = rl.load_render_texture(16, 16)
    try:
        for _ in range(2):
            with texture_mode(target):
                rl.clear_background(rl.BLACK)
                with alpha_test.scope():
                    with pytest.raises(RuntimeError, match="draw failed"), pixel_font.pixel_coverage.scope():
                        raise RuntimeError("draw failed")
                    rl.draw_rectangle(0, 0, 16, 16, rl.Color(255, 0, 0, 3))
            assert _read_rgb(target) == [(0, 0, 0)] * 256
            assert pixel_font.pixel_coverage.shader is not None
            pixel_font.pixel_coverage.close()
            assert pixel_font.pixel_coverage.shader is None
            pixel_font.pixel_coverage.close()
    finally:
        alpha_test.close()
        rl.unload_render_texture(target)


def test_runtime_unload_releases_font_shader(pixel_font: SmallFontData, tmp_path: Path) -> None:
    resources = RuntimeResources(assets_dir=tmp_path, textures={TextureId.SMALL_WHITE: pixel_font.texture}, small_font=pixel_font)
    with pixel_font.pixel_coverage.scope():
        pass
    # The fixture owns the atlas, but resources still owns the font shader.
    resources.textures.clear()
    resources.unload()
    assert pixel_font.pixel_coverage.shader is None
    resources.unload()


@pytest.mark.parametrize("cell_size", [8, 16])
@pytest.mark.parametrize("scale", [1.25, 1.5625, 3.125])
def test_font_does_not_sample_neighboring_atlas_cells(raylib_context, cell_size: int, scale: float) -> None:
    # The drawn cell is transparent, surrounded on all sides by opaque cells.
    # Any light pixels are contamination from a neighboring glyph.
    image = rl.gen_image_color(cell_size * 16, cell_size * 16, rl.WHITE)
    rl.image_draw_rectangle(image, cell_size, 4 * cell_size, cell_size, cell_size, rl.BLANK)
    try:
        texture = rl.load_texture_from_image(image)
    finally:
        rl.unload_image(image)
    rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
    widths = [0] * 256
    widths[ord("A")] = cell_size
    font = SmallFontData(widths=widths, texture=texture, cell_size=cell_size)
    target = rl.load_render_texture(96, 96)
    try:
        with texture_mode(target, scale_x=scale, scale_y=scale):
            rl.clear_background(rl.BLACK)
            draw_small_text(font, "A", Vec2(3, 3), rl.WHITE)
        assert _read_rgb(target) == [(0, 0, 0)] * (96 * 96)
    finally:
        font.pixel_coverage.close()
        rl.unload_render_texture(target)
        rl.unload_texture(texture)


@pytest.mark.parametrize("attempt", range(2))
def test_headless_font_starts_with_fresh_shader_state(headless_resources, headless_window, attempt: int) -> None:
    font = headless_resources.small_font
    assert font.pixel_coverage.shader is None
    assert headless_resources.alpha_test.shader is None
    draw_small_text(font, "A", Vec2(), rl.WHITE)
    assert font.pixel_coverage.shader is not None
    with headless_resources.alpha_test.scope():
        pass


def test_registered_font_has_no_mock_handle_in_real_gl_context(raylib_context, headless_resources, assets_dir) -> None:
    from grim.fonts.small import load_small_font

    font = load_small_font(assets_dir)
    assert font is headless_resources.small_font
    assert font.pixel_coverage.shader is None
    try:
        with font.pixel_coverage.scope():
            assert font.pixel_coverage.shader is not None
            assert font.pixel_coverage.shader.locs != rl.ffi.NULL
    finally:
        font.pixel_coverage.close()


@pytest.mark.parametrize("glyph", ["z", "~"])
@pytest.mark.parametrize("scale", [1.25, 1.5625, 3.125])
def test_real_font_matches_isolated_glyph_atlas(raylib_context, assets_dir: Path, glyph: str, scale: float) -> None:
    entries = assets.load_paq_entries(assets_dir)
    atlas = Image.open(io.BytesIO(entries["load/smallWhite.tga"])).convert("RGBA")
    x, y = ord(glyph) % 16 * 16, ord(glyph) // 16 * 16
    isolated = Image.new("RGBA", atlas.size)
    isolated.paste(atlas.crop((x, y, x + 16, y + 16)), (x, y))
    target = rl.load_render_texture(64, 64)
    outputs = []
    try:
        # z and ~ sit above accented capitals with ink in their first row.
        # Erasing those neighbors must not change the drawn glyph at all.
        for image in (atlas, isolated):
            encoded = io.BytesIO()
            image.save(encoded, format="PNG")
            texture = assets._load_texture_from_bytes(encoded.getvalue(), ".png")
            font = SmallFontData(widths=list(entries["load/smallFnt.dat"]), texture=texture)
            try:
                with texture_mode(target, scale_x=scale, scale_y=scale):
                    rl.clear_background(rl.BLACK)
                    draw_small_text(font, glyph, Vec2(3, 3), rl.WHITE)
                outputs.append(_read_rgb(target))
            finally:
                font.pixel_coverage.close()
                rl.unload_texture(texture)
        assert outputs[0] == outputs[1]
    finally:
        rl.unload_render_texture(target)
