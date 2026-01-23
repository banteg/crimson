from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from .font_grim_mono import GrimMonoFont, draw_grim_mono_text

QUEST_TITLE_ALPHA = 1.0
QUEST_NUMBER_ALPHA_RATIO = 0.5

# Game base scale: 0.75 at 640px width, 0.8 at larger widths.
QUEST_TITLE_SCALE_SMALL = 0.75
QUEST_TITLE_SCALE_LARGE = 0.8
QUEST_TITLE_SCALE_THRESHOLD_PX = 640

# Title overlay baseline is centered vertically and shifted up by 32px (0x20).
QUEST_TITLE_Y_OFFSET = 32.0

# Number is drawn at a slightly smaller scale.
QUEST_NUMBER_SCALE_DELTA = 0.2

# Game X formula: x = title_x - (strlen * scale * 8.0) - (scale * 32.0) - 4.0
# where 8.0 = advance/2, 32.0 = base gap, 4.0 = fixed offset.
QUEST_NUMBER_HALF_ADVANCE = 8.0
QUEST_NUMBER_BASE_GAP = 32.0
QUEST_NUMBER_FIXED_OFFSET = 4.0

# Game Y formula: y = title_y + number_scale * (23.36 - 16.0) = title_y + number_scale * 7.36
QUEST_NUMBER_Y_MULTIPLIER = 7.36


@dataclass(frozen=True, slots=True)
class QuestTitleOverlayLayout:
    title_x: float
    title_y: float
    title_scale: float
    number_x: float
    number_y: float
    number_scale: float


def quest_title_base_scale(screen_width: int) -> float:
    return (
        QUEST_TITLE_SCALE_SMALL
        if screen_width <= QUEST_TITLE_SCALE_THRESHOLD_PX
        else QUEST_TITLE_SCALE_LARGE
    )


def quest_number_scale(title_scale: float) -> float:
    return max(0.0, title_scale - QUEST_NUMBER_SCALE_DELTA)


def layout_quest_title_overlay(
    *,
    screen_width: float,
    screen_height: float,
    title: str,
    number: str,
    font_advance: float,
) -> QuestTitleOverlayLayout:
    title_scale = quest_title_base_scale(int(screen_width))
    number_scale = quest_number_scale(title_scale)

    title_width = len(title) * font_advance * title_scale
    title_x = (screen_width / 2.0) - (title_width / 2.0)
    title_y = (screen_height / 2.0) - QUEST_TITLE_Y_OFFSET

    number_x = (
        title_x
        - (len(number) * number_scale * QUEST_NUMBER_HALF_ADVANCE)
        - (number_scale * QUEST_NUMBER_BASE_GAP)
        - QUEST_NUMBER_FIXED_OFFSET
    )
    number_y = title_y + (number_scale * QUEST_NUMBER_Y_MULTIPLIER)

    return QuestTitleOverlayLayout(
        title_x=title_x,
        title_y=title_y,
        title_scale=title_scale,
        number_x=number_x,
        number_y=number_y,
        number_scale=number_scale,
    )


def draw_quest_title_overlay(font: GrimMonoFont, title: str, number: str) -> None:
    layout = layout_quest_title_overlay(
        screen_width=rl.get_screen_width(),
        screen_height=rl.get_screen_height(),
        title=title,
        number=number,
        font_advance=font.advance,
    )

    title_color = rl.Color(255, 255, 255, int(255 * QUEST_TITLE_ALPHA))
    number_color = rl.Color(
        255, 255, 255, int(255 * QUEST_TITLE_ALPHA * QUEST_NUMBER_ALPHA_RATIO)
    )

    draw_grim_mono_text(
        font, title, layout.title_x, layout.title_y, layout.title_scale, title_color
    )
    draw_grim_mono_text(
        font,
        number,
        layout.number_x,
        layout.number_y,
        layout.number_scale,
        number_color,
    )
