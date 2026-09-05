from __future__ import annotations

from enum import Enum, auto
from typing import TYPE_CHECKING

from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game_modes import GameMode
from ..high_scores_layout import (
    HS_LOCAL_CLOCK_X,
    HS_LOCAL_CLOCK_Y,
    HS_LOCAL_DATE_X,
    HS_LOCAL_DATE_Y,
    HS_LOCAL_FRAGS_X,
    HS_LOCAL_FRAGS_Y,
    HS_LOCAL_HIT_X,
    HS_LOCAL_HIT_Y,
    HS_LOCAL_LABEL_X,
    HS_LOCAL_LABEL_Y,
    HS_LOCAL_NAME_X,
    HS_LOCAL_NAME_Y,
    HS_LOCAL_RANK_X,
    HS_LOCAL_RANK_Y,
    HS_LOCAL_SCORE_LABEL_X,
    HS_LOCAL_SCORE_LABEL_Y,
    HS_LOCAL_SCORE_VALUE_X,
    HS_LOCAL_SCORE_VALUE_Y,
    HS_LOCAL_TIME_LABEL_X,
    HS_LOCAL_TIME_LABEL_Y,
    HS_LOCAL_TIME_VALUE_X,
    HS_LOCAL_TIME_VALUE_Y,
    HS_LOCAL_WEAPON_Y,
    HS_LOCAL_WICON_X,
    HS_LOCAL_WICON_Y,
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
    HS_RIGHT_SHOW_INTERNET_X,
    HS_RIGHT_SHOW_INTERNET_Y,
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
from .shared import format_elapsed_mm_ss, format_score_date, ordinal

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
    scale: float,
) -> None:
    item_count = max(0, len(items))
    header_h = 16.0 * scale
    row_h = 16.0 * scale
    full_h = (float(item_count) * 16.0 + 24.0) * scale
    rows_y0 = widget_pos.y + 17.0 * scale

    mouse = rl.get_mouse_position()
    hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
        mouse,
        pos=widget_pos,
        width=widget_w,
        height=14.0 * scale,
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
        line_h = max(1, int(1.0 * scale))
        rl.draw_rectangle(
            int(widget_pos.x),
            int(widget_pos.y + 15.0 * scale),
            int(widget_w),
            line_h,
            rl.Color(255, 255, 255, 128),
        )

    arrow_tex = (
        resources.texture(TextureId.UI_DROP_ON)
        if ((is_open or hovered_header) and enabled)
        else resources.texture(TextureId.UI_DROP_OFF)
    )
    arrow_w = float(arrow_tex.width) * scale
    arrow_h = float(arrow_tex.height) * scale
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
            height=14.0 * scale,
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
    scale: float,
    highlight_rank: int | None,
) -> None:
    if highlight_rank is None:
        _draw_right_panel_quest_options(
            view,
            resources=resources,
            font=font,
            right_top_left=right_top_left,
            scale=scale,
        )
        return
    _draw_right_panel_local_score(
        view,
        resources=resources,
        font=font,
        right_top_left=right_top_left,
        scale=scale,
        highlight_rank=highlight_rank,
    )


def _draw_right_panel_quest_options(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    right_top_left: Vec2,
    scale: float,
) -> None:
    options_shift_x = hs_right_options_x_shift(float(view.state.config.display.width))
    options_top_left = right_top_left + Vec2(options_shift_x * scale, 0.0)
    text_color = rl.Color(255, 255, 255, int(255 * 0.8))

    # Checkbox: "Show internet scores"
    check_tex = (
        resources.texture(TextureId.UI_CHECK_ON)
        if view.state.config.profile.show_internet_scores
        else resources.texture(TextureId.UI_CHECK_OFF)
    )
    check_w = float(check_tex.width) * scale
    check_h = float(check_tex.height) * scale
    rl.draw_texture_pro(
        check_tex,
        rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
        rl.Rectangle(
            options_top_left.x + HS_RIGHT_CHECK_X * scale,
            options_top_left.y + HS_RIGHT_CHECK_Y * scale,
            check_w,
            check_h,
        ),
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )
    draw_small_text(
        font,
        "Show internet scores",
        options_top_left + Vec2(HS_RIGHT_SHOW_INTERNET_X * scale, HS_RIGHT_SHOW_INTERNET_Y * scale),
        text_color,
    )
    draw_small_text(
        font,
        "Number of players",
        options_top_left + Vec2(HS_RIGHT_NUMBER_PLAYERS_X * scale, HS_RIGHT_NUMBER_PLAYERS_Y * scale),
        text_color,
    )
    draw_small_text(
        font,
        "Game mode",
        options_top_left + Vec2(HS_RIGHT_GAME_MODE_X * scale, HS_RIGHT_GAME_MODE_Y * scale),
        text_color,
    )
    draw_small_text(
        font,
        "Show scores:",
        options_top_left + Vec2(HS_RIGHT_SHOW_SCORES_X * scale, HS_RIGHT_SHOW_SCORES_Y * scale),
        text_color,
    )
    draw_small_text(
        font,
        "Selected score list:",
        options_top_left + Vec2(HS_RIGHT_SCORE_LIST_X * scale, HS_RIGHT_SCORE_LIST_Y * scale),
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
            widget_pos=options_top_left + widget_offset * scale,
            widget_w=widget_w * scale,
            items=items,
            selected_index=selected_index,
            value_pos=options_top_left + value_offset * scale,
            arrow_pos=options_top_left + arrow_offset * scale,
            is_open=is_open,
            enabled=bool(enabled),
            scale=scale,
        )
    for is_open, widget_offset, widget_w, items, selected_index, value_offset, arrow_offset, enabled in dropdowns:
        if not is_open:
            continue
        _draw_dropdown(
            resources=resources,
            font=font,
            widget_pos=options_top_left + widget_offset * scale,
            widget_w=widget_w * scale,
            items=items,
            selected_index=selected_index,
            value_pos=options_top_left + value_offset * scale,
            arrow_pos=options_top_left + arrow_offset * scale,
            is_open=is_open,
            enabled=bool(enabled),
            scale=scale,
        )


def _draw_right_panel_local_score(
    view: HighScoresView,
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    right_top_left: Vec2,
    scale: float,
    highlight_rank: int | None,
) -> None:
    local_shift_x = hs_right_local_card_x_shift(float(view.state.config.display.width))
    card_top_left = right_top_left + Vec2(local_shift_x * scale, 0.0)
    if not view._records:
        return
    idx = int(highlight_rank) if highlight_rank is not None else int(view._scroll_index)
    if idx < 0:
        idx = 0
    if idx >= len(view._records):
        idx = len(view._records) - 1
    entry = view._records[idx]

    text_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.8))
    value_color = rl.Color(int(255 * 0.9), int(255 * 0.9), 255, 255)
    game_time_color = rl.Color(255, 255, 255, int(255 * 0.8))
    lower_section_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.7))
    separator_color = rl.Color(149, 175, 198, int(255 * 0.7))

    name = str(entry.name())
    if not name:
        name = "???"
    draw_small_text(font, name, card_top_left + Vec2(HS_LOCAL_NAME_X * scale, HS_LOCAL_NAME_Y * scale), text_color)
    draw_small_text(
        font, "Local score", card_top_left + Vec2(HS_LOCAL_LABEL_X * scale, HS_LOCAL_LABEL_Y * scale), text_color,
    )
    rl.draw_line(
        int(card_top_left.x + 78.0 * scale),
        int(card_top_left.y + 57.0 * scale),
        int(card_top_left.x + 117.0 * scale),
        int(card_top_left.y + 57.0 * scale),
        separator_color,
    )

    date_text = format_score_date(entry)
    if date_text:
        draw_small_text(
            font, date_text, card_top_left + Vec2(HS_LOCAL_DATE_X * scale, HS_LOCAL_DATE_Y * scale), text_color,
        )
    rl.draw_line(
        int(card_top_left.x + 74.0 * scale),
        int(card_top_left.y + 72.0 * scale),
        int(card_top_left.x + 266.0 * scale),
        int(card_top_left.y + 72.0 * scale),
        separator_color,
    )

    draw_small_text(
        font, "Score", card_top_left + Vec2(HS_LOCAL_SCORE_LABEL_X * scale, HS_LOCAL_SCORE_LABEL_Y * scale), text_color,
    )

    mode_raw = int(entry.game_mode_id)
    try:
        mode_id = GameMode(mode_raw)
    except ValueError:
        mode_id = GameMode.DEMO
    elapsed_ms = int(entry.survival_elapsed_ms)
    score_xp = int(entry.score_xp)
    match mode_id:
        case GameMode.QUESTS:
            time_label = "Experience"
        case _:
            time_label = "Game time"

    draw_small_text(
        font,
        time_label,
        card_top_left + Vec2(HS_LOCAL_TIME_LABEL_X * scale, HS_LOCAL_TIME_LABEL_Y * scale),
        game_time_color,
    )
    rl.draw_line(
        int(card_top_left.x + 170.0 * scale),
        int(card_top_left.y + 90.0 * scale),
        int(card_top_left.x + 170.0 * scale),
        int(card_top_left.y + 138.0 * scale),
        separator_color,
    )

    # Native highscore card:
    # - Rush/Quest: score is survival time in seconds (ms * 0.001), rendered with 2 decimals.
    # - Others: score is XP (u32).
    score_value_pos = Vec2(HS_LOCAL_SCORE_VALUE_X * scale, HS_LOCAL_SCORE_VALUE_Y * scale)
    match mode_id:
        case GameMode.RUSH | GameMode.QUESTS:
            score_value = f"{elapsed_ms * 0.001:.2f} secs"
            # Quest/Rush scores are variable-width second labels ("%.2f secs") and are
            # centered in the left score column in native.
            score_label_w = measure_small_text_width(font, "Score")
            score_value_w = measure_small_text_width(font, score_value)
            score_col_center_x = HS_LOCAL_SCORE_LABEL_X * scale + score_label_w * 0.5
            score_value_pos = Vec2(score_col_center_x - score_value_w * 0.5, HS_LOCAL_SCORE_VALUE_Y * scale)
        case _:
            score_value = f"{score_xp}"
    draw_small_text(font, score_value, card_top_left + score_value_pos, value_color)

    match mode_id:
        case GameMode.QUESTS:
            draw_small_text(
                font,
                f"{score_xp}",
                card_top_left + Vec2(HS_LOCAL_TIME_VALUE_X * scale, HS_LOCAL_TIME_VALUE_Y * scale),
                game_time_color,
            )
        case _:
            _draw_clock_gauge(
                resources=resources,
                elapsed_ms=elapsed_ms,
                pos=card_top_left + Vec2(HS_LOCAL_CLOCK_X * scale, HS_LOCAL_CLOCK_Y * scale),
                scale=scale,
            )
            draw_small_text(
                font,
                format_elapsed_mm_ss(elapsed_ms),
                card_top_left + Vec2(HS_LOCAL_TIME_VALUE_X * scale, HS_LOCAL_TIME_VALUE_Y * scale),
                game_time_color,
            )

    draw_small_text(
        font,
        f"Rank: {ordinal(idx + 1)}",
        card_top_left + Vec2(HS_LOCAL_RANK_X * scale, HS_LOCAL_RANK_Y * scale),
        text_color,
    )

    frags = int(entry.creature_kill_count)

    shots_fired = int(entry.shots_fired)
    shots_hit = int(entry.shots_hit)
    hit_pct = 0
    if shots_fired > 0:
        hit_pct = int((shots_hit * 100) // shots_fired)
    rl.draw_line(
        int(card_top_left.x + 74.0 * scale),
        int(card_top_left.y + 142.0 * scale),
        int(card_top_left.x + 266.0 * scale),
        int(card_top_left.y + 142.0 * scale),
        separator_color,
    )

    weapon_id = entry.most_used_weapon_id
    weapon_name, icon_index = _weapon_label_and_icon(view, weapon_id)
    if icon_index is not None:
        _draw_wicon(
            resources=resources,
            icon_index=icon_index,
            pos=card_top_left + Vec2(HS_LOCAL_WICON_X * scale, HS_LOCAL_WICON_Y * scale),
            scale=scale,
        )
    weapon_name_x = HS_LOCAL_WICON_X * scale + max(
        0.0,
        32.0 * scale - measure_small_text_width(font, weapon_name) * 0.5,
    )
    draw_small_text(
        font, weapon_name, card_top_left + Vec2(weapon_name_x, HS_LOCAL_WEAPON_Y * scale), lower_section_color,
    )
    draw_small_text(
        font,
        f"Frags: {frags}",
        card_top_left + Vec2(HS_LOCAL_FRAGS_X * scale, HS_LOCAL_FRAGS_Y * scale),
        lower_section_color,
    )
    draw_small_text(
        font,
        f"Hit %: {hit_pct}%",
        card_top_left + Vec2(HS_LOCAL_HIT_X * scale, HS_LOCAL_HIT_Y * scale),
        lower_section_color,
    )
    rl.draw_line(
        int(card_top_left.x + 74.0 * scale),
        int(card_top_left.y + 194.0 * scale),
        int(card_top_left.x + 266.0 * scale),
        int(card_top_left.y + 194.0 * scale),
        separator_color,
    )


def _draw_clock_gauge(
    *,
    resources: RuntimeResources,
    elapsed_ms: int,
    pos: Vec2,
    scale: float,
) -> None:
    table_tex = resources.texture(TextureId.UI_CLOCK_TABLE)
    pointer_tex = resources.texture(TextureId.UI_CLOCK_POINTER)
    draw_w = 32.0 * scale
    draw_h = 32.0 * scale
    dst = rl.Rectangle(pos.x, pos.y, draw_w, draw_h)
    src_table = rl.Rectangle(0.0, 0.0, float(table_tex.width), float(table_tex.height))
    src_pointer = rl.Rectangle(0.0, 0.0, float(pointer_tex.width), float(pointer_tex.height))
    rl.draw_texture_pro(
        table_tex,
        src_table,
        dst,
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )
    seconds = max(0, int(elapsed_ms) // 1000)
    rotation_deg = float(seconds) * 6.0
    center = Vec2(pos.x + draw_w * 0.5, pos.y + draw_h * 0.5)
    rl.draw_texture_pro(
        pointer_tex,
        src_pointer,
        rl.Rectangle(center.x, center.y, draw_w, draw_h),
        rl.Vector2(draw_w * 0.5, draw_h * 0.5),
        rotation_deg,
        rl.WHITE,
    )


def _draw_wicon(
    *,
    resources: RuntimeResources,
    icon_index: int,
    pos: Vec2,
    scale: float,
) -> None:
    tex = resources.texture(TextureId.UI_WICONS)
    idx = int(icon_index)
    if idx < 0 or idx > 31:
        return
    grid = 8
    cell_w = float(tex.width) / float(grid)
    cell_h = float(tex.height) / float(grid)
    frame = idx * 2
    src_x = float(frame % grid) * cell_w
    src_y = float(frame // grid) * cell_h
    icon_w = cell_w * 2.0
    icon_h = cell_h
    rl.draw_texture_pro(
        tex,
        rl.Rectangle(src_x, src_y, icon_w, icon_h),
        rl.Rectangle(pos.x, pos.y, icon_w * scale, icon_h * scale),
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )


def _weapon_label_and_icon(view: HighScoresView, weapon_id: int) -> tuple[str, int | None]:
    from ...weapons import WEAPON_BY_ID, WeaponId, weapon_display_name

    weapon = WEAPON_BY_ID[WeaponId(weapon_id)]
    name = weapon_display_name(weapon.weapon_id, preserve_bugs=bool(view.state.preserve_bugs))
    return name, weapon.icon_index


__all__ = ["draw_right_panel"]
