from __future__ import annotations

from collections.abc import Callable

from grim.geom import Vec2
from grim.raylib_api import rl

from ...tutorial import TutorialOverlayState

TUTORIAL_PANEL_POS = Vec2(0.0, 64.0)
TUTORIAL_PANEL_PADDING = Vec2(20.0, 8.0)

DrawUiText = Callable[[str, Vec2, rl.Color, float], None]
MeasureUiTextWidth = Callable[[str, float], float]
MeasureUiLineHeight = Callable[[float], int]


def tutorial_prompt_panel_rect(
    text: str,
    *,
    measure_text_width: MeasureUiTextWidth,
    measure_line_height: MeasureUiLineHeight,
    pos: Vec2,
    scale: float,
) -> tuple[rl.Rectangle, list[str], float]:
    lines = text.splitlines() if text else [""]
    line_h = float(measure_line_height(scale))
    max_w = 0.0
    for line in lines:
        max_w = max(max_w, float(measure_text_width(line, scale)))

    pad_x = TUTORIAL_PANEL_PADDING.x * scale
    pad_y = TUTORIAL_PANEL_PADDING.y * scale
    width = max_w + pad_x * 2.0
    height = float(len(lines)) * line_h + pad_y * 2.0
    screen_w = float(rl.get_screen_width())
    x = (screen_w - width) * 0.5
    rect = rl.Rectangle(float(x), pos.y, float(width), float(height))
    return rect, lines, line_h


def draw_tutorial_prompt_panel(
    text: str,
    *,
    alpha: float,
    pos: Vec2,
    draw_text: DrawUiText,
    measure_text_width: MeasureUiTextWidth,
    measure_line_height: MeasureUiLineHeight,
) -> None:
    if alpha <= 1e-3:
        return
    rect, lines, line_h = tutorial_prompt_panel_rect(
        text,
        measure_text_width=measure_text_width,
        measure_line_height=measure_line_height,
        pos=pos,
        scale=1.0,
    )
    fill = rl.Color(0, 0, 0, int(255 * alpha * 0.8))
    border = rl.Color(255, 255, 255, int(255 * alpha))
    rl.draw_rectangle(int(rect.x), int(rect.y), int(rect.width), int(rect.height), fill)
    rl.draw_rectangle_lines(int(rect.x), int(rect.y), int(rect.width), int(rect.height), border)

    text_alpha = int(255 * min(1.0, max(0.0, alpha * 0.9)))
    color = rl.Color(255, 255, 255, text_alpha)
    x = rect.x + TUTORIAL_PANEL_PADDING.x
    line_y = rect.y + TUTORIAL_PANEL_PADDING.y
    for line in lines:
        draw_text(line, Vec2(x, line_y), color, 1.0)
        line_y += line_h


def draw_tutorial_overlay_panels(
    overlay: TutorialOverlayState,
    *,
    draw_text: DrawUiText,
    measure_text_width: MeasureUiTextWidth,
    measure_line_height: MeasureUiLineHeight,
) -> None:
    if overlay.prompt_text and overlay.prompt_alpha > 1e-3:
        draw_tutorial_prompt_panel(
            overlay.prompt_text,
            alpha=float(overlay.prompt_alpha),
            pos=TUTORIAL_PANEL_POS,
            draw_text=draw_text,
            measure_text_width=measure_text_width,
            measure_line_height=measure_line_height,
        )
    if overlay.hint_text and overlay.hint_alpha > 1e-3:
        draw_tutorial_prompt_panel(
            overlay.hint_text,
            alpha=float(overlay.hint_alpha),
            pos=TUTORIAL_PANEL_POS.offset(dy=84.0),
            draw_text=draw_text,
            measure_text_width=measure_text_width,
            measure_line_height=measure_line_height,
        )
