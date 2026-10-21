"""Resolution-bounded HDR smoke integration with premultiplied reconstruction."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from grim.edr import load_float_render_texture
from grim.raylib_api import rd, rl, rl_rectangle, rl_vector2
from grim.texture_mode import current_target_size, restore_current_target, texture_mode

if TYPE_CHECKING:
    from ..world.viewport import ViewTransform


# Smoke is a low-frequency volume; screen-scale integration should not multiply
# its shader cost on Retina displays. The density field keeps its own resolution.
SMOKE_DISPLAY_MAX_AXIS = 640


def smoke_target_size(width: int, height: int, *, max_axis: int = SMOKE_DISPLAY_MAX_AXIS) -> tuple[int, int]:
    scale = min(1.0, max_axis / max(width, height, 1))
    return max(1, round(width * scale)), max(1, round(height * scale))


class SmokeComposite:
    """Own a reusable viewport-sized, reduced-resolution smoke integration target."""

    def __init__(self) -> None:
        self.target: rl.RenderTexture | None = None

    def draw(self, view: ViewTransform, draw_fields: Callable[[], None]) -> None:
        """Integrate straight-alpha fields, then reconstruct premultiplied radiance.

        ``draw_fields`` uses the original view coordinates and must not change the
        blend mode. The enclosing target's logical-to-physical scale is restored
        by texture_mode before the full-viewport reconstruction.
        """
        width, height = smoke_target_size(*current_target_size())
        if self.target is None or (self.target.texture.width, self.target.texture.height) != (width, height):
            self.close()
            try:
                self.target = load_float_render_texture(width, height)
            finally:
                restore_current_target()
        target = self.target
        out_width, out_height = max(view.out_size.x, 1.), max(view.out_size.y, 1.)
        with texture_mode(target, scale_x=width / out_width, scale_y=height / out_height):
            rl.clear_background(rl.BLANK)
            # Straight RGB becomes premultiplied once; alpha must accumulate as
            # alpha, not alpha squared. Float storage preserves HDR light energy.
            blend = (
                rd.RL_SRC_ALPHA, rd.RL_ONE_MINUS_SRC_ALPHA,
                rd.RL_ONE, rd.RL_ONE_MINUS_SRC_ALPHA,
                rd.RL_FUNC_ADD, rd.RL_FUNC_ADD,
            )
            rl.rl_set_blend_factors_separate(*blend)
            rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM_SEPARATE)
            rl.rl_set_blend_factors_separate(*blend)
            try:
                draw_fields()
            finally:
                rl.end_blend_mode()
        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA_PREMULTIPLY)
        try:
            rl.draw_texture_pro(
                target.texture, rl_rectangle(0, 0, width, -height),
                rl_rectangle(0, 0, out_width, out_height), rl_vector2(0, 0), 0., rl.WHITE,
            )
        finally:
            rl.end_blend_mode()

    def close(self) -> None:
        if self.target is not None:
            rl.unload_render_texture(self.target)
            self.target = None
