from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.quests.level import QuestLevel
from crimson.screens.actions import ScoreQuery
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2

from ...game_modes import GameMode
from ...leaderboard import SyncStatus
from ...quests import quest_by_level
from ...ui.button import button_draw
from ...ui.checkbox import ui_checkbox_draw
from ...ui.scrollbar import ui_scrollbar_draw, ui_scrollbar_row_under_mouse
from ..high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_HARDCORE_CHECKBOX_OFFSET,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_SCORE_FRAME_X,
    HS_SCORE_FRAME_Y,
)
from ..quest_views.shared import QUEST_HARDCORE_UNLOCK_INDEX
from .shared import mode_label

if TYPE_CHECKING:
    from .view import HighScoresView

SYNC_LINES = {
    SyncStatus.CONNECTING: "Connecting...",
    SyncStatus.SENDING: "Sending local scores...",
    SyncStatus.RECEIVING: "Receiving internet scores...",
    SyncStatus.DONE: "Done...",
    SyncStatus.FAILED: "Failed to update scores. Try again later.",
}


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
    # `highscore_screen_update` centres the title 128px into the column at (202, 41) off the panel, on the int
    # text width halved with C integer division, and underlines it at 0.7.
    title_w = int(measure_small_text_width(font, title))
    title_pos = left_panel_top_left + Vec2(float(330 - title_w // 2), 41.0)
    draw_small_text(font, title, title_pos, rl_color(255, 255, 255, 255))
    grim_draw_rect_outline(title_pos.offset(dy=14.0), float(title_w), 1.0, grim_color(1.0, 1.0, 1.0, 0.7))
    if mode_id == GameMode.QUESTS:
        hardcore = view.state.config.gameplay.hardcore
        if hardcore:
            quest_color = rl_color(250, 70, 60, int(255 * 0.7))
        else:
            quest_color = rl_color(70, 180, 240, int(255 * 0.7))
        quest_level = QuestLevel(int(quest_major), int(quest_minor))
        quest = quest_by_level(quest_level)
        quest_label = f"{quest_level.text}: {quest.title if quest is not None else '???'}"
        draw_small_text(font, quest_label, left_panel_top_left + Vec2(236.0, 63.0), quest_color)
        arrow = resources.texture(TextureId.UI_ARROW)
        global_index = int(quest_level.global_index)
        unlock = (
            int(view.state.status.quest_unlock_index_hardcore)
            if view.state.config.gameplay.hardcore
            else int(view.state.status.quest_unlock_index)
        )
        max_index = max(0, min(49, unlock))

        dst_w = float(arrow.width)
        dst_h = float(arrow.height)
        tint = rl_color(255, 255, 255, int(255 * 0.51))

        if global_index > 0:
            src = rl_rectangle(0.0, 0.0, float(arrow.width), float(arrow.height))
            arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X - 255.0, HS_QUEST_ARROW_Y)
            dst = rl_rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
            rl.draw_texture_pro(arrow, src, dst, rl_vector2(0.0, 0.0), 0.0, tint)

        if global_index < max_index:
            # state_14 flips ui_arrow.jaz (uv 1..0) for the right arrow.
            # Keep src.x in-range; with CLAMP wrap, raylib can collapse flipped UVs
            # when the rect starts at x=tex.width.
            src = rl_rectangle(0.0, 0.0, -float(arrow.width), float(arrow.height))
            arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X, HS_QUEST_ARROW_Y)
            dst = rl_rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
            rl.draw_texture_pro(arrow, src, dst, rl_vector2(0.0, 0.0), 0.0, tint)

    if mode_id == GameMode.QUESTS and view.state.status.quest_unlock_index >= QUEST_HARDCORE_UNLOCK_INDEX:
        checkbox = view.hardcore_checkbox
        checkbox.checked = view.state.config.gameplay.hardcore
        ui_checkbox_draw(resources, checkbox, left_panel_top_left + HS_HARDCORE_CHECKBOX_OFFSET, focus=view.state.focus)

    header_color = rl_color(255, 255, 255, 255)
    draw_small_text(font, "Rank", left_panel_top_left + Vec2(211.0, 84.0), header_color)
    draw_small_text(font, "Score", left_panel_top_left + Vec2(246.0, 84.0), header_color)
    draw_small_text(font, "Player", left_panel_top_left + Vec2(302.0, 84.0), header_color)

    mouse = Vec2.from_xy(canvas.mouse_position())
    list_pos = left_panel_top_left + Vec2(HS_SCORE_FRAME_X, HS_SCORE_FRAME_Y)
    ui_scrollbar_draw(font, view.state.focus, view.score_scroll, list_pos, mouse=mouse)
    # The hovered score's card replaces the right panel's options; the port also shows a finished quest's rank.
    selected_rank = request.highlight_rank
    hovered_index = ui_scrollbar_row_under_mouse(view.score_scroll, list_pos, mouse)
    if hovered_index != -1:
        selected_rank = hovered_index
    elif view.pinned is not None:
        selected_rank = view.pinned
    if not view._records:
        draw_small_text(
            font,
            "No scores yet.",
            Vec2(left_panel_top_left.x + 211.0, left_panel_top_left.y + 111.0),
            rl_color(190, 190, 200, 255),
        )

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
    leaderboard = view.state.leaderboard
    if leaderboard is not None and leaderboard.sync_status != SyncStatus.IDLE:
        # `highscore_screen` writes the sync's progress 32px left of the Play button and 32px below it.
        status = leaderboard.sync_status
        color = grim_color(1.0, 0.5, 0.5, 1.0) if status == SyncStatus.FAILED else grim_color(0.5, 1.0, 0.6, 1.0)
        line_pos = button_base_pos + Vec2(-32.0, HS_BUTTON_STEP_Y + 32.0)
        draw_small_text(font, SYNC_LINES[status], line_pos, color)

    return selected_rank


__all__ = ["draw_main_panel"]
