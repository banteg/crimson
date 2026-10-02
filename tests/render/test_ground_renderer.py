from __future__ import annotations

import math
from collections.abc import Iterator, Sequence

import pytest

from grim import canvas
from grim.geom import Vec2
from grim.raylib_api import rd, rl
from grim.shaders import AlphaTestShader
from grim.terrain_render import (
    TERRAIN_BASE_TINT,
    TERRAIN_CLEAR_COLOR,
    TERRAIN_DETAIL_TINT,
    TERRAIN_OVERLAY_TINT,
    GroundCorpseDecal,
    GroundDecal,
    GroundRenderer,
    _terrain_rt_blend,
)
from grim.terrain_stamps import TerrainLayers, TerrainStamp
from grim.texture_mode import texture_mode
from tests.support.helpers import assert_float_close

type Rgba = tuple[int, int, int, int]

RED = rl.Color(255, 0, 0, 255)
GREEN = rl.Color(0, 255, 0, 255)
BLUE = rl.Color(0, 0, 255, 255)
# Alpha 4 is the last value the native ALPHAREF=4 test rejects.
CUTOUT = rl.Color(255, 255, 255, 4)
SENTINEL = rl.Color(255, 0, 255, 255)
NO_STAMPS = TerrainLayers(base=(), overlay=(), detail=())


def _rgba(color: rl.Color) -> Rgba:
    return color.r, color.g, color.b, color.a


def _render_texture(width: int, height: int) -> rl.RenderTexture:
    target = rl.RenderTexture()
    target.id = 1
    target.texture.id = 2
    target.texture.width = width
    target.texture.height = height
    return target


def _ground(**kwargs) -> GroundRenderer:
    texture = rl.Texture()
    return GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture, **kwargs)


class _Gpu:
    """Uploads test textures, targets and grounds in the live GL context; releases them after the test."""

    def __init__(self) -> None:
        self._textures: list[rl.Texture] = []
        self._targets: list[rl.RenderTexture] = []
        self._grounds: list[GroundRenderer] = []

    def texture(self, rows: Sequence[Sequence[rl.Color]]) -> rl.Texture:
        image = rl.gen_image_color(len(rows[0]), len(rows), rl.BLANK)
        for y, row in enumerate(rows):
            for x, color in enumerate(row):
                rl.image_draw_pixel(image, x, y, color)
        texture = rl.load_texture_from_image(image)
        rl.unload_image(image)
        self._textures.append(texture)
        return texture

    def target(self, width: int, height: int) -> rl.RenderTexture:
        target = rl.load_render_texture(width, height)
        self._targets.append(target)
        return target

    def ground(self, **kwargs) -> GroundRenderer:
        ground = _ground(**kwargs)
        self._grounds.append(ground)
        return ground

    def close(self) -> None:
        for ground in self._grounds:
            ground.close()
        for target in self._targets:
            rl.unload_render_texture(target)
        for texture in self._textures:
            rl.unload_texture(texture)


@pytest.fixture
def gpu(raylib_context) -> Iterator[_Gpu]:
    gpu = _Gpu()
    try:
        yield gpu
    finally:
        gpu.close()


def _read(texture: rl.Texture, points: Sequence[tuple[int, int]]) -> list[Rgba]:
    image = rl.load_image_from_texture(texture)
    try:
        # Render targets are stored bottom-up; flip to the top-left origin they were drawn in.
        rl.image_flip_vertical(image)
        return [_rgba(rl.get_image_color(image, x, y)) for x, y in points]
    finally:
        rl.unload_image(image)


def _read_world(ground: GroundRenderer, points: Sequence[tuple[float, float]]) -> list[Rgba]:
    """Ground target pixels at terrain-space points, whatever the target's DPI and texture scale."""
    assert ground.render_target is not None
    ratio = ground.render_target.texture.width / ground.width
    return _read(ground.render_target.texture, [(int(x * ratio), int(y * ratio)) for x, y in points])


def _over(color: rl.Color, tint: rl.Color, dst: rl.Color) -> tuple[float, ...]:
    """`color * tint` blended over `dst` with SRC_ALPHA/INV_SRC_ALPHA, alpha writes masked."""
    alpha = color.a * tint.a / 255.0**2
    src = (color.r * tint.r / 255.0, color.g * tint.g / 255.0, color.b * tint.b / 255.0)
    return (*(s * alpha + d * (1.0 - alpha) for s, d in zip(src, (dst.r, dst.g, dst.b), strict=True)), dst.a)


def _cell_color(cx: int, cy: int) -> rl.Color:
    return rl.Color(40 + 60 * cx, 40 + 60 * cy, 128, 255)


def _grid_ground(gpu: _Gpu) -> GroundRenderer:
    """A 64x64 ground whose target shows a 4x4 grid of 16-unit cells, each a distinct color."""
    grid = gpu.texture([[_cell_color(cx, cy) for cx in range(4)] for cy in range(4)])
    ground = gpu.ground(width=64, height=64)
    ground.schedule_stamps(NO_STAMPS, texture_scale=1.0)
    ground.process_pending()
    decal = GroundDecal(
        texture=grid,
        src=rl.Rectangle(0.0, 0.0, 4.0, 4.0),
        pos=Vec2(32.0, 32.0),
        width=64.0,
        height=64.0,
    )
    assert ground.bake_decals((decal,))
    return ground


def _cells(target: rl.RenderTexture, points: Sequence[tuple[int, int]]) -> list[tuple[int, ...]]:
    """The grid cell shown at each output pixel, or the raw color where no cell is."""
    cells = {_rgba(_cell_color(cx, cy)): (cx, cy) for cx in range(4) for cy in range(4)}
    return [cells.get(rgba, rgba) for rgba in _read(target.texture, points)]


def test_draw_view_maps_the_explicit_window_onto_the_output_without_refit_or_clamp(gpu: _Gpu) -> None:
    ground = _grid_ground(gpu)
    target = gpu.target(80, 48)
    with texture_mode(target):
        rl.clear_background(SENTINEL)
        # The camera is past the clamp limit (-32), and a 32x32 window is not the 2:1 output's fit.
        ground.draw_view(Vec2(-40.0, -16.0), screen_w=32.0, screen_h=32.0, out_w=64.0, out_h=32.0)

    # Output pixel centers sample terrain (40 + (x + 0.5) / 2, 16 + y + 0.5).
    assert _cells(target, [(10, 20), (20, 4), (70, 10), (10, 40)]) == [
        (2, 2),
        (3, 1),
        _rgba(SENTINEL),
        _rgba(SENTINEL),
    ]


def test_draw_fits_and_clamps_the_window_to_the_canvas_size(gpu: _Gpu, mocker) -> None:
    ground = _grid_ground(gpu)
    mocker.patch.object(canvas, "width", return_value=96)
    mocker.patch.object(canvas, "height", return_value=48)
    target = gpu.target(112, 56)
    with texture_mode(target):
        rl.clear_background(SENTINEL)
        ground.draw(Vec2(5.0, -40.0))

    # A 96x48 canvas fits a 64x32 window at scale 1.5 and clamps the camera to (0, -32), so
    # output pixel centers sample terrain ((x + 0.5) / 1.5, 32 + (y + 0.5) / 1.5).
    assert _cells(target, [(40, 20), (80, 40), (100, 10), (10, 52)]) == [
        (1, 2),
        (3, 3),
        _rgba(SENTINEL),
        _rgba(SENTINEL),
    ]


def test_draw_view_without_render_target_fills_the_output_with_the_clear_color(gpu: _Gpu) -> None:
    ground = gpu.ground()
    target = gpu.target(80, 48)
    with texture_mode(target):
        rl.clear_background(SENTINEL)
        ground.draw_view(Vec2(-1.0, -1.0), screen_w=32.0, screen_h=32.0, out_w=64.0, out_h=32.0)

    clear = _rgba(TERRAIN_CLEAR_COLOR)
    assert _read(target.texture, [(0, 0), (63, 31), (70, 10), (10, 40)]) == [
        clear,
        clear,
        _rgba(SENTINEL),
        _rgba(SENTINEL),
    ]


def test_generated_stamps_draw_each_layer_with_its_texture_and_tint_under_alpha_test(gpu: _Gpu) -> None:
    ground = gpu.ground(width=256, height=256)
    ground.texture = gpu.texture([[RED, CUTOUT]])
    ground.overlay = gpu.texture([[GREEN]])
    ground.overlay_detail = gpu.texture([[BLUE]])
    ground.schedule_stamps(
        TerrainLayers(
            base=(TerrainStamp(0.0, 0.0, 0.0),),
            overlay=(TerrainStamp(0.0, 128.0, 0.0),),
            detail=(TerrainStamp(0.0, 0.0, 128.0),),
        ),
        texture_scale=1.0,
    )
    ground.process_pending()
    assert ground.render_target_ready()

    base, cutout, overlay, detail, bare = _read_world(ground, [(32, 64), (96, 64), (192, 64), (64, 192), (192, 192)])
    assert base == pytest.approx(_over(RED, TERRAIN_BASE_TINT, TERRAIN_CLEAR_COLOR), abs=1)
    assert overlay == pytest.approx(_over(GREEN, TERRAIN_OVERLAY_TINT, TERRAIN_CLEAR_COLOR), abs=1)
    assert detail == pytest.approx(_over(BLUE, TERRAIN_DETAIL_TINT, TERRAIN_CLEAR_COLOR), abs=1)
    # Without the alpha test the alpha-4 texel would still nudge the ground by ~2 levels.
    assert cutout == _rgba(TERRAIN_CLEAR_COLOR)
    assert bare == _rgba(TERRAIN_CLEAR_COLOR)


def test_bake_decals_point_sample_under_alpha_test(gpu: _Gpu) -> None:
    ground = gpu.ground(width=64, height=64)
    ground.schedule_stamps(NO_STAMPS, texture_scale=1.0)
    ground.process_pending()
    decal = GroundDecal(
        texture=gpu.texture([[RED, GREEN, CUTOUT]]),
        src=rl.Rectangle(0.0, 0.0, 3.0, 1.0),
        pos=Vec2(32.0, 32.0),
        width=48.0,
        height=16.0,
    )

    assert ground.bake_decals((decal,)) is True

    assert ground.render_target_ready()
    # Texels span 16 units from x=8; bilinear filtering would mix a quarter of green into red at x=20.
    assert _read_world(ground, [(20, 32), (32, 32), (48, 32), (4, 32)]) == [
        _rgba(RED),
        _rgba(GREEN),
        _rgba(TERRAIN_CLEAR_COLOR),
        _rgba(TERRAIN_CLEAR_COLOR),
    ]


def test_bake_corpse_decals_draw_the_frame_cell_point_sampled_over_its_shadow(gpu: _Gpu) -> None:
    ground = gpu.ground(width=64, height=64)
    ground.schedule_stamps(NO_STAMPS, texture_scale=1.0)
    ground.process_pending()
    # Frame 3 is the top-right 2x2 cell of a 4x4 bodyset: a red texel column, then a green one.
    frame_cell = {6: RED, 7: GREEN}
    bodyset = gpu.texture([[frame_cell.get(x, BLUE) if y < 2 else BLUE for x in range(8)] for y in range(8)])
    decal = GroundCorpseDecal(
        bodyset_frame=3,
        top_left=Vec2(16.0, 16.0),
        size=32.0,
        rotation_rad=math.pi * 0.5,
    )

    assert ground.bake_corpse_decals(bodyset, (decal,)) is True

    # The texel columns span 16 units from x=16; bilinear filtering would mix green into red at x=28.
    # The 1.064x shadow quad reaches past the color quad's right edge at x=48, halving the ground there.
    red, green, shadow = _read_world(ground, [(28, 32), (40, 32), (48.75, 32)])
    assert red == _rgba(RED)
    assert green == _rgba(GREEN)
    clear = TERRAIN_CLEAR_COLOR
    assert shadow == pytest.approx((*(c * (1.0 - 127 / 255) for c in (clear.r, clear.g, clear.b)), clear.a), abs=1)


@pytest.mark.parametrize(("initial_dpi", "bake_dpi"), [(1, 1), (2, 2), (1, 2), (2, 1)])
@pytest.mark.parametrize("canvas_scale", [1, 2, 3])
@pytest.mark.parametrize("corpse", [False, True], ids=["blood", "corpse"])
def test_baked_decals_keep_world_size_after_dpi_changes(
    gpu: _Gpu, mocker, initial_dpi: int, bake_dpi: int, canvas_scale: int, corpse: bool,
) -> None:
    mocker.patch.object(rl, "get_window_scale_dpi", return_value=rl.Vector2(initial_dpi, initial_dpi))
    ground = gpu.ground(width=64, height=64)
    ground.schedule_stamps(NO_STAMPS, texture_scale=1.0)
    ground.process_pending()
    texture = gpu.texture([[RED] * 4] * 4)
    output = gpu.target(64 * canvas_scale, 64 * canvas_scale)

    # The existing terrain target survives a window/monitor DPI change. Canvas
    # scales the whole frame, while decal baking must retain terrain-space units.
    mocker.patch.object(rl, "get_window_scale_dpi", return_value=rl.Vector2(bake_dpi, bake_dpi))
    with texture_mode(output, scale_x=canvas_scale, scale_y=canvas_scale):
        if corpse:
            assert ground.bake_corpse_decals(
                texture,
                (GroundCorpseDecal(0, Vec2(8.0, 8.0), 16.0, math.pi * 0.5),),
            )
        else:
            assert ground.bake_decals(
                (GroundDecal(texture, rl.Rectangle(0.0, 0.0, 4.0, 4.0), Vec2(16.0, 16.0), 16.0, 16.0),),
            )
        ground.draw_view(Vec2(), screen_w=64, screen_h=64, out_w=64, out_h=64)

    # A 16-unit decal occupies x=8..24 in every case. Sampling both inside and
    # beyond that span catches the doubled/halved size and displaced position.
    pixels = _read(output.texture, [(x * canvas_scale, 16 * canvas_scale) for x in (12, 20, 26, 32)])
    assert pixels == [_rgba(RED), _rgba(RED), _rgba(TERRAIN_CLEAR_COLOR), _rgba(TERRAIN_CLEAR_COLOR)]


def test_terrain_rt_blend_keeps_target_alpha_and_restores_alpha_writes(gpu: _Gpu) -> None:
    target = gpu.target(16, 16)
    translucent = rl.Color(255, 0, 0, 128)
    with texture_mode(target):
        rl.clear_background(rl.BLACK)
        with _terrain_rt_blend(rd.RL_SRC_ALPHA, rd.RL_ONE_MINUS_SRC_ALPHA, rd.RL_FUNC_ADD):
            rl.draw_rectangle(0, 0, 8, 16, translucent)
        rl.draw_rectangle(8, 0, 8, 16, translucent)

    masked, blended = _read(target.texture, [(4, 8), (12, 8)])
    assert masked == pytest.approx((128, 0, 0, 255), abs=1)
    # Alpha blends like color once writes are back on: 0.5 * 0.5 + 1.0 * 0.5.
    assert blended == pytest.approx((128, 0, 0, 191), abs=1)


def test_draw_stamps_scales_native_top_left_into_raylib_origin(headless_window, mocker) -> None:
    mocker.patch.object(rl, "get_window_scale_dpi", return_value=rl.Vector2(1.0, 1.0))
    ground = _ground()
    ground.render_target = _render_texture(512, 512)
    texture = rl.Texture()
    texture.width = 128
    texture.height = 128

    ground._draw_stamps(texture, TERRAIN_BASE_TINT, (TerrainStamp(rotation=1.5, x=-64.0, y=100.0),))

    (_, src, dst, origin, degrees, tint), _ = headless_window.draw_texture_pro.call_args
    assert (src.x, src.y, src.width, src.height) == (0.0, 0.0, 128.0, 128.0)
    # `position *= inv_scale` gives the top-left (-32, 50); raylib places the 64-unit quad by its center.
    assert (dst.x, dst.y, dst.width, dst.height) == (0.0, 82.0, 64.0, 64.0)
    assert (origin.x, origin.y) == (32.0, 32.0)
    assert_float_close(degrees, 85.94366926962348)
    assert tint == TERRAIN_BASE_TINT


def test_bake_decals_returns_false_without_render_target() -> None:
    decal = GroundDecal(
        texture=rl.Texture(),
        src=rl.Rectangle(0.0, 0.0, 16.0, 16.0),
        pos=Vec2(10.0, 10.0),
        width=16.0,
        height=16.0,
    )

    assert _ground().bake_decals((decal,)) is False


# A live GL context can't be made to fail on demand, so the tests below inject
# failures at the raylib boundary and hand out render-target structs in its place.


def test_alpha_test_shader_invalid_handle_raises(mocker) -> None:
    mocker.patch.object(rl, "load_shader_from_memory", return_value=rl.Shader())
    alpha_test = AlphaTestShader()

    with pytest.raises(RuntimeError, match="invalid shader id"), alpha_test.scope():
        pass
    assert alpha_test.shader is None


def test_ensure_render_target_recovers_after_previous_failure(mocker) -> None:
    ground = _ground()
    candidate = _render_texture(1024, 1024)
    mocker.patch.object(rl, "load_render_texture", return_value=candidate)
    mocker.patch.object(rl, "rl_framebuffer_complete", side_effect=[False, True])
    mocker.patch.object(rl, "set_texture_filter")
    mocker.patch.object(rl, "set_texture_wrap")
    unload = mocker.patch.object(rl, "unload_render_texture")

    ground._ensure_render_target(1.0)
    assert ground.texture_failed is True
    assert ground.render_target is None
    unload.assert_called_once_with(candidate)

    ground._ensure_render_target(1.0)
    assert ground.texture_failed is False
    assert ground.render_target is candidate


def test_load_render_target_rejects_incomplete_framebuffer(mocker) -> None:
    ground = _ground()
    candidate = _render_texture(1024, 1024)
    mocker.patch.object(rl, "load_render_texture", return_value=candidate)
    mocker.patch.object(rl, "rl_framebuffer_complete", return_value=False)
    unload = mocker.patch.object(rl, "unload_render_texture")

    assert ground._load_render_target(1024, 1024) is False
    unload.assert_called_once_with(candidate)


def test_render_target_setup_failure_releases_candidate(mocker) -> None:
    ground = _ground()
    candidate = _render_texture(1024, 1024)
    mocker.patch.object(rl, "load_render_texture", return_value=candidate)
    mocker.patch.object(rl, "rl_framebuffer_complete", return_value=True)
    mocker.patch.object(rl, "set_texture_filter", side_effect=RuntimeError("setup failed"))
    unload = mocker.patch.object(rl, "unload_render_texture")

    with pytest.raises(RuntimeError, match="setup failed"):
        ground._load_render_target(1024, 1024)
    unload.assert_called_once_with(candidate)
    assert ground.render_target is None


def test_process_pending_clears_failed_schedule_after_terminal_rt_failure(mocker) -> None:
    ground = _ground()
    load = mocker.patch.object(rl, "load_render_texture", return_value=_render_texture(1024, 1024))
    mocker.patch.object(rl, "rl_framebuffer_complete", return_value=False)
    mocker.patch.object(rl, "unload_render_texture")

    ground.schedule_stamps(NO_STAMPS, texture_scale=1.0)
    ground.process_pending()
    ground.process_pending()

    assert ground.texture_failed is True
    load.assert_called_once()


def test_generation_failure_unbinds_target_and_retains_pending_stamps(headless_window, mocker) -> None:
    mocker.patch.object(rl, "get_window_scale_dpi", return_value=rl.Vector2(1.0, 1.0))
    mocker.patch.object(rl, "load_shader_from_memory", side_effect=RuntimeError("compile failed"))
    ground = _ground()
    ground.render_target = _render_texture(1024, 1024)
    ground._render_target_ready = True
    layers = TerrainLayers(base=(), overlay=(), detail=())
    ground.schedule_stamps(layers, texture_scale=1.0)

    with pytest.raises(RuntimeError, match="compile failed"):
        ground.process_pending()

    headless_window.end_texture_mode.assert_called_once_with()
    assert not ground.render_target_ready()
    assert ground._scheduled_layers is layers
