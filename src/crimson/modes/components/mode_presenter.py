from __future__ import annotations

from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...world.runtime import WorldRuntime


def draw_world_runtime(
    runtime: WorldRuntime,
    *,
    draw_aim_indicators: bool = True,
    entity_alpha: float = 1.0,
) -> None:
    runtime.render_resources.bake_fx_queues()
    runtime.renderer.draw(
        render_frame=runtime.build_render_frame(),
        draw_aim_indicators=draw_aim_indicators,
        entity_alpha=entity_alpha,
    )


def draw_ui_text(
    font: SmallFontData,
    text: str,
    pos: Vec2,
    color: rl.Color,
    *,
    scale: float = 1.0,
) -> None:
    _ = scale
    draw_small_text(font, text, pos, color)


def measure_ui_text_width(
    font: SmallFontData,
    text: str,
    *,
    scale: float = 1.0,
) -> float:
    _ = scale
    return float(measure_small_text_width(font, text))
