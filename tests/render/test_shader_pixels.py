from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from grim.raylib_api import rl
from grim.shaders import AlphaTestShader


def _rgb(image: rl.Image, x: int, y: int) -> tuple[int, int, int]:
    color = rl.get_image_color(image, x, y)
    return color.r, color.g, color.b


def test_alpha_test_cutoff_and_default_shader_restoration(raylib_context) -> None:
    alpha_test = AlphaTestShader()
    target = rl.load_render_texture(64, 16)
    try:
        # Run twice to exercise release and lazy reload in the same GL context.
        for _ in range(2):
            rl.begin_texture_mode(target)
            try:
                rl.clear_background(rl.BLACK)
                with alpha_test.scope():
                    for i, alpha in enumerate((4, 5, 255)):
                        rl.draw_rectangle(i * 16, 0, 16, 16, rl.Color(255, 0, 0, alpha))
                rl.draw_rectangle(48, 0, 16, 16, rl.Color(255, 0, 0, 4))
            finally:
                rl.end_texture_mode()
            image = rl.load_image_from_texture(target.texture)
            try:
                assert [_rgb(image, x, 8)[0] for x in (8, 24, 40, 56)] == [0, 5, 255, 4]
            finally:
                rl.unload_image(image)
            alpha_test.close()
    finally:
        alpha_test.close()
        rl.unload_render_texture(target)


@pytest.mark.parametrize("gain", [1.0, 1.5])
def test_gamma_covers_inner_shader_and_later_drawing_at_display_resolution(
    raylib_context,
    make_game_state,
    mocker,
    gain: float,
) -> None:
    view = GameLoopView(make_game_state())
    view.state.gamma_ramp = gain
    alpha_test = AlphaTestShader()
    screen_w, screen_h = rl.get_screen_width(), rl.get_screen_height()

    def draw_scene() -> None:
        rl.clear_background(rl.Color(20, 30, 40, 255))
        with alpha_test.scope():
            rl.draw_rectangle(0, 0, screen_w // 2, screen_h // 2, rl.Color(60, 80, 100, 255))
        rl.draw_rectangle(screen_w // 2, screen_h // 2, screen_w // 2, screen_h // 2, rl.Color(100, 120, 140, 255))

    mocker.patch.object(view, "_draw_scene_layers", side_effect=draw_scene)
    try:
        rl.begin_drawing()
        try:
            view.draw()
            rl.rl_draw_render_batch_active()
            image = rl.load_image_from_screen()
            try:
                assert (image.width, image.height) == (rl.get_render_width(), rl.get_render_height())
                if gain != 1.0:
                    assert view._gamma_target is not None
                    assert (view._gamma_target.texture.width, view._gamma_target.texture.height) == (
                        image.width,
                        image.height,
                    )
                for x, y, rgb in (
                    (image.width // 4, image.height // 4, (60, 80, 100)),
                    (image.width * 3 // 4, image.height // 4, (20, 30, 40)),
                    (image.width // 4, image.height * 3 // 4, (20, 30, 40)),
                    (image.width * 3 // 4, image.height * 3 // 4, (100, 120, 140)),
                ):
                    assert _rgb(image, x, y) == pytest.approx(tuple(c * gain for c in rgb), abs=1)
            finally:
                rl.unload_image(image)
        finally:
            rl.end_drawing()
    finally:
        alpha_test.close()
        view._close_gamma_resources()
