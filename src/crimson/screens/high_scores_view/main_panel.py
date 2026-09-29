from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.quests.level import QuestLevel
from crimson.screens.actions import ScoreQuery
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game_modes import GameMode
from ...quests import quest_by_level
from ...ui.checkbox import ui_checkbox_draw
from ...ui.perk_menu import button_draw
from ...ui.scrollbar import ui_scrollbar_draw_focus
from ..high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_HARDCORE_CHECKBOX_OFFSET,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_SCORE_FRAME_H,
    HS_SCORE_FRAME_W,
    HS_SCORE_FRAME_X,
    HS_SCORE_FRAME_Y,
    HS_TITLE_UNDERLINE_Y,
)
from ..quest_views.shared import QUEST_HARDCORE_UNLOCK_INDEX
from .shared import mode_label

if TYPE_CHECKING:
    from .view import HighScoresView


_SCORE_ROW_STEP = 16.0
_SCORE_ROWS_Y = 103.0


def score_row_under_mouse(view: HighScoresView, left_panel_top_left: Vec2) -> int | None:
    """The score row the mouse is on (`ui_scrollbar_t.hovered_index`); its card replaces the right panel."""
    mouse = Vec2.from_xy(canvas.mouse_position())
    frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X
    frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y
    y = left_panel_top_left.y + _SCORE_ROWS_Y
    rows = view.score_scroll.visible_rows
    if not (
        frame_x <= mouse.x < frame_x + HS_SCORE_FRAME_W
        and frame_y <= mouse.y < frame_y + HS_SCORE_FRAME_H
        and y <= mouse.y < y + _SCORE_ROW_STEP * rows
    ):
        return None
    start = max(0, int(view.score_scroll.scroll_offset))
    index = start + int((mouse.y - y) // _SCORE_ROW_STEP)
    if index < min(len(view._records), start + rows):
        return index
    return None


def draw_main_panel(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    left_panel_top_left: Vec2,
    mode_id: GameMode,
    quest_major: int,
    quest_minor: int,
    request: ScoreQuery,
) -> int | None:
    match mode_id:
        case GameMode.QUESTS:
            title = "High scores - Quests"
        case _:
            title = f"High scores - {mode_label(mode_id, quest_major, quest_minor)}"
    title_x = 269.0
    match mode_id:
        case GameMode.SURVIVAL:
            # state_14:High scores - Survival title at x=168 (panel left_x0 is -98).
            title_x = 266.0
        case _:
            pass
    title_draw_pos = left_panel_top_left + Vec2(title_x, 41.0)
    draw_small_text(font, title, title_draw_pos, rl.Color(255, 255, 255, 255))
    ul_w = measure_small_text_width(font, title)
    ul_pos = left_panel_top_left + Vec2(title_x, HS_TITLE_UNDERLINE_Y)
    rl.draw_rectangle(
        int(round(ul_pos.x)),
        int(round(ul_pos.y)),
        int(round(ul_w)),
        1,
        rl.Color(255, 255, 255, int(255 * 0.7)),
    )
    if mode_id == GameMode.QUESTS:
        hardcore = view.state.config.gameplay.hardcore
        if hardcore:
            quest_color = rl.Color(250, 70, 60, int(255 * 0.7))
        else:
            quest_color = rl.Color(70, 180, 240, int(255 * 0.7))
        quest_level = QuestLevel(int(quest_major), int(quest_minor))
        quest = quest_by_level(quest_level)
        quest_label = f"{quest_level.text}: {quest.title if quest is not None else '???'}"
        draw_small_text(font, quest_label, left_panel_top_left + Vec2(236.0, 63.0), quest_color)
        arrow = resources.texture(TextureId.UI_ARROW)
        global_index = int(quest_level.global_index)
        unlock = (
            int(view.state.status.quest_unlock_index_full)
            if view.state.config.gameplay.hardcore
            else int(view.state.status.quest_unlock_index)
        )
        max_index = max(0, min(49, unlock))

        dst_w = float(arrow.width)
        dst_h = float(arrow.height)
        tint = rl.Color(255, 255, 255, int(255 * 0.51))

        if global_index > 0:
            src = rl.Rectangle(0.0, 0.0, float(arrow.width), float(arrow.height))
            arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X - 255.0, HS_QUEST_ARROW_Y)
            dst = rl.Rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
            rl.draw_texture_pro(arrow, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)

        if global_index < max_index:
            # state_14 flips ui_arrow.jaz (uv 1..0) for the right arrow.
            # Keep src.x in-range; with CLAMP wrap, raylib can collapse flipped UVs
            # when the rect starts at x=tex.width.
            src = rl.Rectangle(0.0, 0.0, -float(arrow.width), float(arrow.height))
            arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X, HS_QUEST_ARROW_Y)
            dst = rl.Rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
            rl.draw_texture_pro(arrow, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)

    if mode_id == GameMode.QUESTS and view.state.status.quest_unlock_index >= QUEST_HARDCORE_UNLOCK_INDEX:
        checkbox = view.hardcore_checkbox
        checkbox.checked = view.state.config.gameplay.hardcore
        ui_checkbox_draw(resources, checkbox, left_panel_top_left + HS_HARDCORE_CHECKBOX_OFFSET, focus=view.state.focus)

    header_color = rl.Color(255, 255, 255, 255)
    draw_small_text(font, "Rank", left_panel_top_left + Vec2(211.0, 84.0), header_color)
    draw_small_text(font, "Score", left_panel_top_left + Vec2(246.0, 84.0), header_color)
    draw_small_text(font, "Player", left_panel_top_left + Vec2(302.0, 84.0), header_color)

    # Score list viewport frame (white 1px border + black interior).
    frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X
    frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y
    frame_w = HS_SCORE_FRAME_W
    frame_h = HS_SCORE_FRAME_H
    ui_scrollbar_draw_focus(view.state.focus, view.score_scroll, Vec2(frame_x, frame_y))
    rl.draw_rectangle(int(round(frame_x)), int(round(frame_y)), int(round(frame_w)), int(round(frame_h)), rl.WHITE)
    rl.draw_rectangle(
        int(round(frame_x + 1.0)),
        int(round(frame_y + 1.0)),
        max(0, int(round(frame_w - 2.0))),
        max(0, int(round(frame_h - 2.0))),
        rl.BLACK,
    )

    row_step = _SCORE_ROW_STEP
    start = max(0, int(view.score_scroll.scroll_offset))
    end = min(len(view._records), start + view.score_scroll.visible_rows)
    y = left_panel_top_left.y + _SCORE_ROWS_Y
    selected_rank = (
        int(request.highlight_rank) if (request.highlight_rank is not None) else None
    )
    hovered_idx = score_row_under_mouse(view, left_panel_top_left)
    if hovered_idx is not None:
        selected_rank = hovered_idx

    if start >= end:
        draw_small_text(
            font,
            "No scores yet.",
            Vec2(left_panel_top_left.x + 211.0, y + 8.0),
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

            match mode_id:
                case GameMode.RUSH | GameMode.QUESTS:
                    elapsed_ms = int(entry.survival_elapsed_ms)
                    value = f"{int(elapsed_ms / 1000)}"
                case _:
                    value = f"{int(entry.score_xp)}"

            color = rl.Color(255, 255, 255, int(255 * 0.7))
            if selected_rank is not None and int(selected_rank) == idx:
                color = rl.Color(255, 255, 255, 255)

            draw_small_text(font, f"{idx + 1}", Vec2(left_panel_top_left.x + 216.0, y), color)
            draw_small_text(font, value, Vec2(left_panel_top_left.x + 246.0, y), color)
            draw_small_text(font, name, Vec2(left_panel_top_left.x + 304.0, y), color)
            y += row_step

    button_base_pos = left_panel_top_left + Vec2(HS_BUTTON_X, HS_BUTTON_Y0)
    focus = view.state.focus
    button_draw(resources, view._update_button, focus=focus, pos=button_base_pos)
    button_draw(
        resources,
        view._play_button,
        focus=focus,
        pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y),
    )
    button_draw(
        resources,
        view._back_button,
        focus=focus,
        pos=left_panel_top_left + Vec2(HS_BACK_BUTTON_X, HS_BACK_BUTTON_Y),
    )

    return selected_rank


__all__ = ["draw_main_panel"]
