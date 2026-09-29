from __future__ import annotations

from typing import TYPE_CHECKING

from grim import canvas
from grim.assets import RuntimeResources
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game_states import GameStateId
from ...ui.checkbox import ui_checkbox_draw
from ...ui.dropdown import ui_list_widget_draw
from ...ui.highscore_card import ui_text_input_render
from ...ui.perk_menu import button_draw
from ...ui.text_input import ui_text_input_draw, ui_text_input_draw_focus
from ..high_scores_layout import (
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_GAME_MODE_WIDGET,
    HS_RIGHT_GAME_MODE_X,
    HS_RIGHT_GAME_MODE_Y,
    HS_RIGHT_NUMBER_PLAYERS_X,
    HS_RIGHT_NUMBER_PLAYERS_Y,
    HS_RIGHT_PLAYER_COUNT_WIDGET,
    HS_RIGHT_SCORE_LIST_WIDGET,
    HS_RIGHT_SCORE_LIST_X,
    HS_RIGHT_SCORE_LIST_Y,
    HS_RIGHT_SHOW_SCORES_WIDGET,
    HS_RIGHT_SHOW_SCORES_X,
    HS_RIGHT_SHOW_SCORES_Y,
    PROFILE_NAME_INPUT_W,
    hs_right_local_card_x_shift,
    hs_right_options_x_shift,
)

if TYPE_CHECKING:
    from .view import HighScoresView


def draw_right_panel(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    right_top_left: Vec2,
    highlight_rank: int | None,
) -> None:
    if highlight_rank is None:
        _draw_right_panel_quest_options(
            view,
            resources=resources,
            font=font,
            right_top_left=right_top_left,
        )
        return
    _draw_right_panel_local_score(
        view,
        resources=resources,
        right_top_left=right_top_left,
        highlight_rank=highlight_rank,
    )


def _draw_right_panel_quest_options(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    right_top_left: Vec2,
) -> None:
    options_shift_x = hs_right_options_x_shift(float(view.state.config.display.width))
    options_top_left = right_top_left + Vec2(options_shift_x, 0.0)
    text_color = rl.Color(255, 255, 255, int(255 * 0.8))

    checkbox = view.internet_checkbox
    checkbox.checked = view.state.config.profile.show_internet_scores
    focus = view.state.focus
    ui_checkbox_draw(resources, checkbox, options_top_left + Vec2(HS_RIGHT_CHECK_X, HS_RIGHT_CHECK_Y), focus=focus)
    draw_small_text(
        font,
        "Number of players",
        options_top_left + Vec2(HS_RIGHT_NUMBER_PLAYERS_X, HS_RIGHT_NUMBER_PLAYERS_Y),
        text_color,
    )
    draw_small_text(
        font,
        "Game mode",
        options_top_left + Vec2(HS_RIGHT_GAME_MODE_X, HS_RIGHT_GAME_MODE_Y),
        text_color,
    )
    draw_small_text(
        font,
        "Show scores:",
        options_top_left + Vec2(HS_RIGHT_SHOW_SCORES_X, HS_RIGHT_SHOW_SCORES_Y),
        text_color,
    )
    draw_small_text(
        font,
        "Selected score list:",
        options_top_left + Vec2(HS_RIGHT_SCORE_LIST_X, HS_RIGHT_SCORE_LIST_Y),
        text_color,
    )

    # `ui_profile_menu_update` draws the name box and Add, or Delete, before its list opens over them.
    profile_pos = options_top_left + HS_RIGHT_SCORE_LIST_WIDGET
    if view._profile_add_mode:
        input_pos = profile_pos.offset(dy=29.0)
        ui_text_input_draw_focus(focus, view._profile_name_field, input_pos)
        ui_text_input_draw(
            resources, input_pos, width=PROFILE_NAME_INPUT_W, text=view._profile_name, caret=view._profile_caret,
        )
        button_draw(resources, view._profile_add_button, focus=focus, pos=profile_pos + Vec2(180.0, 22.0))
    elif not view._profile_list_open and view.state.config.profile.selected_saved_name_slot != 0:
        button_draw(resources, view._profile_delete_button, focus=focus, pos=profile_pos.offset(dy=22.0))

    # `highscore_screen` draws the lists in update order, so an open list covers the ones below it.
    view.sync_lists()
    mouse = Vec2.from_xy(canvas.mouse_position())
    for widget, offset in (
        (view.score_list, HS_RIGHT_SCORE_LIST_WIDGET),
        (view.date_filter_list, HS_RIGHT_SHOW_SCORES_WIDGET),
        (view.player_count_list, HS_RIGHT_PLAYER_COUNT_WIDGET),
        (view.game_mode_list, HS_RIGHT_GAME_MODE_WIDGET),
    ):
        ui_list_widget_draw(resources, widget, options_top_left + offset, focus=focus, mouse=mouse)


def _draw_right_panel_local_score(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    right_top_left: Vec2,
    highlight_rank: int | None,
) -> None:
    if not view._records:
        return
    idx = int(highlight_rank) if highlight_rank is not None else int(view.score_scroll.scroll_offset)
    idx = max(0, min(idx, len(view._records) - 1))
    local_shift_x = hs_right_local_card_x_shift(float(view.state.config.display.width))
    ui_text_input_render(
        right_top_left + Vec2(local_shift_x + 74.0, 44.0), view._records[idx], 1.0, idx + 1,
        game_state=GameStateId.HIGHSCORES, ui_phase=0, resources=resources, mouse=canvas.mouse_position(), dt=view._dt,
    )


__all__ = ["draw_right_panel"]
