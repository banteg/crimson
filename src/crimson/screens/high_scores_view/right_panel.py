from __future__ import annotations

from enum import Enum, auto
from typing import TYPE_CHECKING

from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game_states import GameStateId
from ...ui.checkbox import ui_checkbox_draw
from ...ui.highscore_card import ui_text_input_render
from ..high_scores_layout import (
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_GAME_MODE_DROP_X,
    HS_RIGHT_GAME_MODE_DROP_Y,
    HS_RIGHT_GAME_MODE_VALUE_X,
    HS_RIGHT_GAME_MODE_VALUE_Y,
    HS_RIGHT_GAME_MODE_WIDGET_W,
    HS_RIGHT_GAME_MODE_WIDGET_X,
    HS_RIGHT_GAME_MODE_WIDGET_Y,
    HS_RIGHT_GAME_MODE_X,
    HS_RIGHT_GAME_MODE_Y,
    HS_RIGHT_NUMBER_PLAYERS_X,
    HS_RIGHT_NUMBER_PLAYERS_Y,
    HS_RIGHT_PLAYER_COUNT_DROP_X,
    HS_RIGHT_PLAYER_COUNT_DROP_Y,
    HS_RIGHT_PLAYER_COUNT_VALUE_X,
    HS_RIGHT_PLAYER_COUNT_VALUE_Y,
    HS_RIGHT_PLAYER_COUNT_WIDGET_W,
    HS_RIGHT_PLAYER_COUNT_WIDGET_X,
    HS_RIGHT_PLAYER_COUNT_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_DROP_X,
    HS_RIGHT_SCORE_LIST_DROP_Y,
    HS_RIGHT_SCORE_LIST_VALUE_X,
    HS_RIGHT_SCORE_LIST_VALUE_Y,
    HS_RIGHT_SCORE_LIST_WIDGET_W,
    HS_RIGHT_SCORE_LIST_WIDGET_X,
    HS_RIGHT_SCORE_LIST_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_X,
    HS_RIGHT_SCORE_LIST_Y,
    HS_RIGHT_SHOW_SCORES_DROP_X,
    HS_RIGHT_SHOW_SCORES_DROP_Y,
    HS_RIGHT_SHOW_SCORES_VALUE_X,
    HS_RIGHT_SHOW_SCORES_VALUE_Y,
    HS_RIGHT_SHOW_SCORES_WIDGET_W,
    HS_RIGHT_SHOW_SCORES_WIDGET_X,
    HS_RIGHT_SHOW_SCORES_WIDGET_Y,
    HS_RIGHT_SHOW_SCORES_X,
    HS_RIGHT_SHOW_SCORES_Y,
    hs_right_local_card_x_shift,
    hs_right_options_x_shift,
)
from ..panels.hit_test import mouse_inside_rect_with_padding

if TYPE_CHECKING:
    from .view import HighScoresView


class ScoreDropdown(Enum):
    DATE = auto()
    PLAYERS = auto()
    MODE = auto()
    PROFILE = auto()


def _saved_score_names(view: HighScoresView) -> list[str]:
    return list(view.state.config.profile.saved_name_labels())


def _draw_dropdown(
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    widget_pos: Vec2,
    widget_w: float,
    items: list[str] | tuple[str, ...],
    selected_index: int,
    value_pos: Vec2,
    arrow_pos: Vec2,
    is_open: bool,
    enabled: bool,
) -> None:
    item_count = max(0, len(items))
    header_h = 16.0
    row_h = 16.0
    full_h = float(item_count) * 16.0 + 24.0
    rows_y0 = widget_pos.y + 17.0

    mouse = canvas.mouse_position()
    hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
        mouse,
        pos=widget_pos,
        width=widget_w,
        height=14.0,
    )

    widget_h = full_h if is_open else header_h
    rl.draw_rectangle(int(widget_pos.x), int(widget_pos.y), int(widget_w), int(widget_h), rl.WHITE)
    rl.draw_rectangle(
        int(widget_pos.x) + 1,
        int(widget_pos.y) + 1,
        max(0, int(widget_w) - 2),
        max(0, int(widget_h) - 2),
        rl.BLACK,
    )

    if (is_open or hovered_header) and enabled:
        rl.draw_rectangle(
            int(widget_pos.x),
            int(widget_pos.y + 15.0),
            int(widget_w),
            1,
            rl.Color(255, 255, 255, 128),
        )

    arrow_tex = (
        resources.texture(TextureId.UI_DROP_ON)
        if ((is_open or hovered_header) and enabled)
        else resources.texture(TextureId.UI_DROP_OFF)
    )
    arrow_w = float(arrow_tex.width)
    arrow_h = float(arrow_tex.height)
    rl.draw_texture_pro(
        arrow_tex,
        rl.Rectangle(0.0, 0.0, float(arrow_tex.width), float(arrow_tex.height)),
        rl.Rectangle(arrow_pos.x, arrow_pos.y, arrow_w, arrow_h),
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )

    if item_count <= 0:
        return

    selected_index = max(0, min(item_count - 1, int(selected_index)))
    header_alpha = 242 if ((is_open or hovered_header) and enabled) else 191
    draw_small_text(font, str(items[selected_index]), value_pos, rl.Color(255, 255, 255, header_alpha))

    if not is_open:
        return

    for idx, label in enumerate(items):
        item_y = rows_y0 + row_h * float(idx)
        hovered = bool(enabled) and mouse_inside_rect_with_padding(
            mouse,
            pos=Vec2(widget_pos.x, item_y),
            width=widget_w,
            height=14.0,
        )
        alpha = 153
        if hovered:
            alpha = 242
        if idx == selected_index:
            alpha = max(alpha, 245)
        draw_small_text(font, str(label), Vec2(value_pos.x, item_y), rl.Color(255, 255, 255, alpha))


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

    # Dropdown widgets (state_14 quest variant).
    show_scores_items = ("Best of all time", "Best of month", "Best of week", "Best of day")
    player_items = ("1 player", "2 players", "3 players", "4 players")
    mode_items: list[tuple[str, int]] = [("Quests", 3), ("Rush", 2), ("Survival", 1)]
    if int(view.state.status.quest_unlock_index) >= 0x28:
        mode_items.append(("Typ'o'Shooter", 4))
    names = _saved_score_names(view)

    player_count = max(1, min(4, view.state.config.gameplay.player_count))
    player_selected = player_count - 1
    show_scores_selected = max(0, min(len(show_scores_items) - 1, int(view.state.config.profile.score_date_mode)))
    mode_id = view.state.config.gameplay.mode
    mode_selected = 0
    for idx, (_label, _id) in enumerate(mode_items):
        if int(_id) == int(mode_id):
            mode_selected = idx
            break
    name_selected = max(0, min(len(names) - 1, int(view.state.config.profile.selected_saved_name_slot)))

    dropdowns = (
        (
            (view._dropdown is ScoreDropdown.PLAYERS),
            Vec2(HS_RIGHT_PLAYER_COUNT_WIDGET_X, HS_RIGHT_PLAYER_COUNT_WIDGET_Y),
            float(HS_RIGHT_PLAYER_COUNT_WIDGET_W),
            list(player_items),
            player_selected,
            Vec2(HS_RIGHT_PLAYER_COUNT_VALUE_X, HS_RIGHT_PLAYER_COUNT_VALUE_Y),
            Vec2(HS_RIGHT_PLAYER_COUNT_DROP_X, HS_RIGHT_PLAYER_COUNT_DROP_Y),
            not (view._dropdown in {ScoreDropdown.MODE, ScoreDropdown.DATE, ScoreDropdown.PROFILE}),
        ),
        (
            (view._dropdown is ScoreDropdown.MODE),
            Vec2(HS_RIGHT_GAME_MODE_WIDGET_X, HS_RIGHT_GAME_MODE_WIDGET_Y),
            float(HS_RIGHT_GAME_MODE_WIDGET_W),
            [label for label, _id in mode_items],
            mode_selected,
            Vec2(HS_RIGHT_GAME_MODE_VALUE_X, HS_RIGHT_GAME_MODE_VALUE_Y),
            Vec2(HS_RIGHT_GAME_MODE_DROP_X, HS_RIGHT_GAME_MODE_DROP_Y),
            not (view._dropdown in {ScoreDropdown.PLAYERS, ScoreDropdown.DATE, ScoreDropdown.PROFILE}),
        ),
        (
            (view._dropdown is ScoreDropdown.DATE),
            Vec2(HS_RIGHT_SHOW_SCORES_WIDGET_X, HS_RIGHT_SHOW_SCORES_WIDGET_Y),
            float(HS_RIGHT_SHOW_SCORES_WIDGET_W),
            list(show_scores_items),
            show_scores_selected,
            Vec2(HS_RIGHT_SHOW_SCORES_VALUE_X, HS_RIGHT_SHOW_SCORES_VALUE_Y),
            Vec2(HS_RIGHT_SHOW_SCORES_DROP_X, HS_RIGHT_SHOW_SCORES_DROP_Y),
            not (view._dropdown in {ScoreDropdown.PLAYERS, ScoreDropdown.MODE, ScoreDropdown.PROFILE}),
        ),
        (
            (view._dropdown is ScoreDropdown.PROFILE),
            Vec2(HS_RIGHT_SCORE_LIST_WIDGET_X, HS_RIGHT_SCORE_LIST_WIDGET_Y),
            float(HS_RIGHT_SCORE_LIST_WIDGET_W),
            names,
            name_selected,
            Vec2(HS_RIGHT_SCORE_LIST_VALUE_X, HS_RIGHT_SCORE_LIST_VALUE_Y),
            Vec2(HS_RIGHT_SCORE_LIST_DROP_X, HS_RIGHT_SCORE_LIST_DROP_Y),
            not (view._dropdown in {ScoreDropdown.PLAYERS, ScoreDropdown.MODE, ScoreDropdown.DATE}),
        ),
    )
    # Active list must render last so overlapping widgets don't occlude open options.
    for is_open, widget_offset, widget_w, items, selected_index, value_offset, arrow_offset, enabled in dropdowns:
        if is_open:
            continue
        _draw_dropdown(
            resources=resources,
            font=font,
            widget_pos=options_top_left + widget_offset,
            widget_w=widget_w,
            items=items,
            selected_index=selected_index,
            value_pos=options_top_left + value_offset,
            arrow_pos=options_top_left + arrow_offset,
            is_open=is_open,
            enabled=bool(enabled),
        )
    for is_open, widget_offset, widget_w, items, selected_index, value_offset, arrow_offset, enabled in dropdowns:
        if not is_open:
            continue
        _draw_dropdown(
            resources=resources,
            font=font,
            widget_pos=options_top_left + widget_offset,
            widget_w=widget_w,
            items=items,
            selected_index=selected_index,
            value_pos=options_top_left + value_offset,
            arrow_pos=options_top_left + arrow_offset,
            is_open=is_open,
            enabled=bool(enabled),
        )


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
