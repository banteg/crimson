from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import TypeAlias

from grim.geom import Vec2
from grim.raylib_api import rl

from ...creatures.runtime import CreatureState

NAME_LABEL_SCALE = 1.0
NAME_LABEL_BG_ALPHA = 0.67

TYPING_PANEL_WIDTH = 182.0
TYPING_PANEL_HEIGHT = 53.0
TYPING_PANEL_ALPHA = 0.7
TYPING_TEXT_X = 6.0
TYPING_PROMPT = ">"
TYPING_CURSOR = "_"
TYPING_CURSOR_X_OFFSET = 14.0

DrawUiText: TypeAlias = Callable[[str, Vec2, rl.Color, float], None]
MeasureUiTextWidth: TypeAlias = Callable[[str, float], float]
WorldToScreen: TypeAlias = Callable[[Vec2], Vec2]


def draw_typo_name_labels(
    *,
    creatures: Sequence[CreatureState],
    names: Sequence[str],
    world_to_screen: WorldToScreen,
    draw_text: DrawUiText,
    measure_text_width: MeasureUiTextWidth,
) -> None:
    if not names:
        return

    for idx, creature in enumerate(creatures):
        if not creature.active:
            continue
        if not (0 <= idx < len(names)):
            continue
        text = names[idx]
        if not text:
            continue

        label_alpha = 1.0
        lifecycle_stage = float(creature.lifecycle_stage)
        if lifecycle_stage < 0.0:
            label_alpha = max(0.0, min(1.0, (lifecycle_stage + 10.0) * 0.1))
        if label_alpha <= 1e-3:
            continue

        screen_pos = world_to_screen(creature.pos)
        y = screen_pos.y - 50.0
        text_w = float(measure_text_width(text, NAME_LABEL_SCALE))
        text_h = 15.0
        x = screen_pos.x - text_w * 0.5

        bg_alpha = label_alpha * NAME_LABEL_BG_ALPHA
        bg = rl.Color(0, 0, 0, int(255 * bg_alpha))
        fg = rl.Color(255, 255, 255, int(255 * label_alpha))
        rl.draw_rectangle_rec(rl.Rectangle(x - 4.0, y, text_w + 8.0, text_h), bg)
        draw_text(text, Vec2(x, y), fg, NAME_LABEL_SCALE)


def draw_typing_box(
    panel_texture: rl.Texture,
    *,
    text: str,
    cursor_pulse_time: float,
    draw_text: DrawUiText,
    measure_text_width: MeasureUiTextWidth,
) -> None:
    screen_h = float(rl.get_screen_height())
    panel_x = -1.0
    panel_y = screen_h - 144.0
    text_y = screen_h - 127.0

    src = rl.Rectangle(0.0, 0.0, float(panel_texture.width), float(panel_texture.height))
    dst = rl.Rectangle(
        panel_x,
        panel_y,
        TYPING_PANEL_WIDTH,
        TYPING_PANEL_HEIGHT,
    )
    tint = rl.Color(255, 255, 255, int(255 * TYPING_PANEL_ALPHA))
    rl.draw_texture_pro(panel_texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)

    draw_text(TYPING_PROMPT + text, Vec2(TYPING_TEXT_X, text_y), rl.Color(255, 255, 255, 255), 1.0)

    cursor_dim = math.sin(float(cursor_pulse_time) * 4.0) > 0.0
    cursor_alpha = 0.4 if cursor_dim else 1.0
    cursor_color = rl.Color(255, 255, 255, int(255 * cursor_alpha))
    text_w = float(measure_text_width(text, 1.0))
    cursor_x = text_w + TYPING_CURSOR_X_OFFSET
    draw_text(TYPING_CURSOR, Vec2(cursor_x, text_y), cursor_color, 1.0)
