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
    ui_checkbox_draw(resources, checkbox, options_top_left + Vec2(HS_RIGHT_CHECK_X, HS_RIGHT_CHECK_Y))
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

    # `highscore_screen` draws the lists in update order, so an open list covers the ones below it.
    view.sync_lists()
    mouse = Vec2.from_xy(canvas.mouse_position())
    ui_list_widget_draw(resources, view.score_list, options_top_left + HS_RIGHT_SCORE_LIST_WIDGET, mouse=mouse)
    ui_list_widget_draw(resources, view.date_filter_list, options_top_left + HS_RIGHT_SHOW_SCORES_WIDGET, mouse=mouse)
    ui_list_widget_draw(resources, view.player_count_list, options_top_left + HS_RIGHT_PLAYER_COUNT_WIDGET, mouse=mouse)
    ui_list_widget_draw(resources, view.game_mode_list, options_top_left + HS_RIGHT_GAME_MODE_WIDGET, mouse=mouse)


def _draw_right_panel_local_score(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    right_top_left: Vec2,
    highlight_rank: int | None,
) -> None:
    if not view._records:
        return
    idx = int(highlight_rank) if highlight_rank is not None else int(view._scroll_index)
    idx = max(0, min(idx, len(view._records) - 1))
    local_shift_x = hs_right_local_card_x_shift(float(view.state.config.display.width))
    ui_text_input_render(
        right_top_left + Vec2(local_shift_x + 74.0, 44.0), view._records[idx], 1.0, idx + 1,
        game_state=GameStateId.HIGHSCORES, ui_phase=0, resources=resources, mouse=canvas.mouse_position(), dt=view._dt,
    )


__all__ = ["draw_right_panel"]
