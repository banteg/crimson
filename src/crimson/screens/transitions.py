from __future__ import annotations

from grim.raylib_api import rl

from .types import ScreenContext

SCREEN_FADE_OUT_RATE = 2.0
SCREEN_FADE_IN_RATE = 10.0


def _update_screen_fade(state: ScreenContext, dt: float) -> None:
    if state.screen_fade_ramp:
        state.screen_fade_alpha += float(dt) * SCREEN_FADE_IN_RATE
    else:
        state.screen_fade_alpha -= float(dt) * SCREEN_FADE_OUT_RATE
    if state.screen_fade_alpha < 0.0:
        state.screen_fade_alpha = 0.0
    elif state.screen_fade_alpha > 1.0:
        state.screen_fade_alpha = 1.0


def _draw_screen_fade(state: ScreenContext) -> None:
    alpha = float(state.screen_fade_alpha)
    if alpha <= 0.0:
        return
    shade = int(max(0.0, min(1.0, alpha)) * 255.0)
    rl.draw_rectangle(0, 0, int(rl.get_screen_width()), int(rl.get_screen_height()), rl.Color(0, 0, 0, shade))
