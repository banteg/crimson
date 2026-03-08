from __future__ import annotations

from collections.abc import Callable

from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...world.runtime import WorldRuntime

FallbackMeasureFn = Callable[[str, float], float]


def draw_world_runtime(
    runtime: WorldRuntime | None,
    *,
    draw_aim_indicators: bool = True,
    entity_alpha: float = 1.0,
) -> None:
    if runtime is None:
        return
    runtime.render_resources.bake_fx_queues()
    runtime.renderer.draw(
        render_frame=runtime.build_render_frame(),
        draw_aim_indicators=draw_aim_indicators,
        entity_alpha=entity_alpha,
    )


def draw_ui_text(
    font: SmallFontData | None,
    text: str,
    pos: Vec2,
    color: rl.Color,
    *,
    scale: float = 1.0,
) -> None:
    if font is not None:
        draw_small_text(font, text, pos, color)
        return
    rl.draw_text(text, int(pos.x), int(pos.y), int(20 * scale), color)


def measure_ui_text_width(
    font: SmallFontData | None,
    text: str,
    *,
    scale: float = 1.0,
    fallback: FallbackMeasureFn | None = None,
) -> float:
    if font is not None:
        return float(measure_small_text_width(font, text))
    if fallback is not None:
        return float(fallback(text, scale))
    return float(rl.measure_text(text, int(20 * scale)))
