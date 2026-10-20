from __future__ import annotations

import pytest

import grim.fonts.small as small_module
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.shaders import AlphaTestShader, PixelCoverageShader


def _font(*, width: int = 7) -> SmallFontData:
    widths = [0] * 256
    widths[ord("A")] = int(width)
    return SmallFontData(widths=widths, texture=rl.Texture())


def test_draw_small_text_preserves_full_glyph_uvs_and_logical_positions(mocker, headless_window) -> None:
    font = _font(width=7)
    draw_texture_pro = mocker.patch.object(small_module.rl, "draw_texture_pro")

    draw_small_text(font, "A", Vec2(10.4, 20.6), rl.WHITE)

    assert draw_texture_pro.call_count == 1
    src = draw_texture_pro.call_args.args[1]
    dst = draw_texture_pro.call_args.args[2]

    assert (float(src.x), float(src.y), float(src.width), float(src.height)) == (16.0, 64.0, 7.0, 16.0)
    assert (float(dst.x), float(dst.y), float(dst.width), float(dst.height)) == (10.0, 20.0, 7.0, 16.0)


def test_small_text_metrics_are_fixed_scale() -> None:
    font = _font(width=7)
    assert measure_small_text_width(font, "A\nAA") == 14.0


@pytest.mark.parametrize("shader_type", [AlphaTestShader, PixelCoverageShader])
def test_shader_rejects_compile_fallback(mocker, shader_type) -> None:
    fallback = rl.Shader()
    fallback.id = 3
    mocker.patch.object(rl, "load_shader_from_memory", return_value=fallback)
    mocker.patch.object(rl, "rl_get_shader_id_default", return_value=3)
    begin = mocker.patch.object(rl, "begin_shader_mode")
    unload = mocker.patch.object(rl, "unload_shader")
    shader = shader_type()
    with pytest.raises(RuntimeError, match="shader compilation failed"), shader.scope():
        pass
    assert shader.shader is None
    shader.close()
    begin.assert_not_called()
    unload.assert_not_called()


@pytest.mark.parametrize("uniform", ["alphaCutoff", "cellSize"])
@pytest.mark.parametrize("failure", ["missing", "raises"])
def test_pixel_coverage_uniform_failure_releases_candidate_and_allows_retry(mocker, uniform: str, failure: str) -> None:
    candidate, replacement = rl.Shader(), rl.Shader()
    candidate.id, replacement.id = 7, 8
    mocker.patch.object(rl, "load_shader_from_memory", side_effect=[candidate, replacement])
    mocker.patch.object(rl, "rl_get_shader_id_default", return_value=3)

    def locate(shader, name):
        if name == uniform:
            if failure == "raises":
                raise RuntimeError("lookup failed")
            return -1
        return 0

    lookup = mocker.patch.object(rl, "get_shader_location", side_effect=locate)
    begin = mocker.patch.object(rl, "begin_shader_mode")
    mocker.patch.object(rl, "end_shader_mode")
    mocker.patch.object(rl, "set_shader_value")
    unload = mocker.patch.object(rl, "unload_shader")
    shader = PixelCoverageShader()
    with pytest.raises(RuntimeError), shader.scope():
        pass
    assert shader.shader is None
    assert shader._alpha_cutoff_loc == -1
    assert shader._cell_size_loc == -1
    unload.assert_called_once_with(candidate)
    begin.assert_not_called()
    lookup.side_effect = None
    lookup.return_value = 0
    with shader.scope():
        assert shader.shader is replacement
    shader.close()
    assert unload.call_args.args == (replacement,)
