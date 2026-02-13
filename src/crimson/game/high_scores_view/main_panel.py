from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.geom import Vec2
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width

from ...frontend.high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_SCORE_FRAME_H,
    HS_SCORE_FRAME_W,
    HS_SCORE_FRAME_X,
    HS_SCORE_FRAME_Y,
    HS_TITLE_UNDERLINE_Y,
)
from ...ui.perk_menu import button_draw, button_width
from ..types import HighScoresRequest
from .shared import mode_label, quest_title

if TYPE_CHECKING:
    from .view import HighScoresView


def draw_main_panel(
    view: "HighScoresView",
    *,
    font: SmallFontData,
    left_panel_top_left: Vec2,
    scale: float,
    mode_id: int,
    quest_major: int,
    quest_minor: int,
    request: HighScoresRequest | None,
) -> int | None:
    title = (
        "High scores - Quests"
        if int(mode_id) == 3
        else f"High scores - {mode_label(mode_id, quest_major, quest_minor)}"
    )
    title_x = 269.0
    if int(mode_id) == 1:
        # state_14:High scores - Survival title at x=168 (panel left_x0 is -98).
        title_x = 266.0
    title_draw_pos = left_panel_top_left + Vec2(title_x * scale, 41.0 * scale)
    draw_small_text(
        font,
        title,
        title_draw_pos,
        1.0 * scale,
        rl.Color(255, 255, 255, 255),
    )
    ul_w = measure_small_text_width(font, title, 1.0 * scale)
    ul_h = max(1, int(round(1.0 * scale)))
    ul_pos = left_panel_top_left + Vec2(title_x * scale, HS_TITLE_UNDERLINE_Y * scale)
    rl.draw_rectangle(
        int(round(ul_pos.x)),
        int(round(ul_pos.y)),
        int(round(ul_w)),
        ul_h,
        rl.Color(255, 255, 255, int(255 * 0.7)),
    )
    if int(mode_id) == 3:
        hardcore = view.state.config.hardcore
        if hardcore:
            quest_color = rl.Color(250, 70, 60, int(255 * 0.7))
        else:
            quest_color = rl.Color(70, 180, 240, int(255 * 0.7))
        quest_label = f"{int(quest_major)}.{int(quest_minor)}: {quest_title(quest_major, quest_minor)}"
        draw_small_text(
            font,
            quest_label,
            left_panel_top_left + Vec2(236.0 * scale, 63.0 * scale),
            1.0 * scale,
            quest_color,
        )
        arrow = view._arrow_tex
        if arrow is not None:
            dst_w = float(arrow.width) * scale
            dst_h = float(arrow.height) * scale
            # state_14 draws ui_arrow.jaz flipped (uv 1..0) to point left.
            src = rl.Rectangle(float(arrow.width), 0.0, -float(arrow.width), float(arrow.height))
            arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X * scale, HS_QUEST_ARROW_Y * scale)
            dst = rl.Rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
            rl.draw_texture_pro(arrow, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

    header_color = rl.Color(255, 255, 255, 255)
    draw_small_text(font, "Rank", left_panel_top_left + Vec2(211.0 * scale, 84.0 * scale), 1.0 * scale, header_color)
    draw_small_text(font, "Score", left_panel_top_left + Vec2(246.0 * scale, 84.0 * scale), 1.0 * scale, header_color)
    draw_small_text(font, "Player", left_panel_top_left + Vec2(302.0 * scale, 84.0 * scale), 1.0 * scale, header_color)

    # Score list viewport frame (white 1px border + black interior).
    frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X * scale
    frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y * scale
    frame_w = HS_SCORE_FRAME_W * scale
    frame_h = HS_SCORE_FRAME_H * scale
    rl.draw_rectangle(int(round(frame_x)), int(round(frame_y)), int(round(frame_w)), int(round(frame_h)), rl.WHITE)
    rl.draw_rectangle(
        int(round(frame_x + 1.0 * scale)),
        int(round(frame_y + 1.0 * scale)),
        max(0, int(round(frame_w - 2.0 * scale))),
        max(0, int(round(frame_h - 2.0 * scale))),
        rl.BLACK,
    )

    row_step = 16.0 * scale
    rows = 10
    start = max(0, int(view._scroll_index))
    end = min(len(view._records), start + rows)
    y = left_panel_top_left.y + 103.0 * scale
    selected_rank = int(request.highlight_rank) if (request is not None and request.highlight_rank is not None) else None
    mouse = Vec2.from_xy(rl.get_mouse_position())
    frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X * scale
    frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y * scale
    frame_w = HS_SCORE_FRAME_W * scale
    frame_h = HS_SCORE_FRAME_H * scale
    if (
        frame_x <= mouse.x < frame_x + frame_w
        and frame_y <= mouse.y < frame_y + frame_h
        and y <= mouse.y < y + row_step * rows
    ):
        row = int((mouse.y - y) // row_step)
        hovered_idx = start + row
        if start <= hovered_idx < end:
            selected_rank = hovered_idx

    if start >= end:
        draw_small_text(
            font,
            "No scores yet.",
            Vec2(left_panel_top_left.x + 211.0 * scale, y + 8.0 * scale),
            1.0 * scale,
            rl.Color(190, 190, 200, 255),
        )
    else:
        for idx in range(start, end):
            entry = view._records[idx]
            name = str(entry.name())
            if not name:
                name = "???"
            if len(name) > 16:
                name = name[:16]

            value = f"{int(getattr(entry, 'score_xp', 0))}"

            color = rl.Color(255, 255, 255, int(255 * 0.7))
            if selected_rank is not None and int(selected_rank) == idx:
                color = rl.Color(255, 255, 255, 255)

            draw_small_text(font, f"{idx + 1}", Vec2(left_panel_top_left.x + 216.0 * scale, y), 1.0 * scale, color)
            draw_small_text(font, value, Vec2(left_panel_top_left.x + 246.0 * scale, y), 1.0 * scale, color)
            draw_small_text(font, name, Vec2(left_panel_top_left.x + 304.0 * scale, y), 1.0 * scale, color)
            y += row_step

    textures = view._button_textures
    if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
        button_base_pos = left_panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
        w = button_width(font, view._update_button.label, scale=scale, force_wide=view._update_button.force_wide)
        button_draw(textures, font, view._update_button, pos=button_base_pos, width=w, scale=scale)
        w = button_width(font, view._play_button.label, scale=scale, force_wide=view._play_button.force_wide)
        button_draw(
            textures,
            font,
            view._play_button,
            pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
            width=w,
            scale=scale,
        )
        w = button_width(font, view._back_button.label, scale=scale, force_wide=view._back_button.force_wide)
        button_draw(
            textures,
            font,
            view._back_button,
            pos=left_panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
            width=w,
            scale=scale,
        )

    return selected_rank


__all__ = ["draw_main_panel"]
