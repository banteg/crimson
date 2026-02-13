from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.geom import Vec2
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width

from ...frontend.high_scores_layout import (
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
)
from .shared import format_elapsed_mm_ss, format_score_date, ordinal

if TYPE_CHECKING:
    from .view import HighScoresView


def draw_right_panel(
    view: "HighScoresView",
    *,
    font: SmallFontData,
    right_top_left: Vec2,
    scale: float,
    highlight_rank: int | None,
) -> None:
    if highlight_rank is None:
        _draw_right_panel_quest_options(view, font=font, right_top_left=right_top_left, scale=scale)
        return
    _draw_right_panel_local_score(
        view,
        font=font,
        right_top_left=right_top_left,
        scale=scale,
        highlight_rank=highlight_rank,
    )


def _draw_right_panel_quest_options(
    view: "HighScoresView",
    *,
    font: SmallFontData,
    right_top_left: Vec2,
    scale: float,
) -> None:
    text_scale = 1.0 * scale
    text_color = rl.Color(255, 255, 255, int(255 * 0.8))

    check_on = view._check_on
    if check_on is not None:
        check_w = float(check_on.width) * scale
        check_h = float(check_on.height) * scale
        rl.draw_texture_pro(
            check_on,
            rl.Rectangle(0.0, 0.0, float(check_on.width), float(check_on.height)),
            rl.Rectangle(
                right_top_left.x + HS_RIGHT_CHECK_X * scale,
                right_top_left.y + HS_RIGHT_CHECK_Y * scale,
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
        right_top_left + Vec2(HS_RIGHT_SHOW_INTERNET_X * scale, HS_RIGHT_SHOW_INTERNET_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Number of players",
        right_top_left + Vec2(HS_RIGHT_NUMBER_PLAYERS_X * scale, HS_RIGHT_NUMBER_PLAYERS_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Game mode",
        right_top_left + Vec2(HS_RIGHT_GAME_MODE_X * scale, HS_RIGHT_GAME_MODE_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Show scores:",
        right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_X * scale, HS_RIGHT_SHOW_SCORES_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Selected score list:",
        right_top_left + Vec2(HS_RIGHT_SCORE_LIST_X * scale, HS_RIGHT_SCORE_LIST_Y * scale),
        text_scale,
        text_color,
    )

    # Closed list widgets (state_14 quest variant): white border + black fill.
    widget_h = 16.0 * scale
    for widget_offset, widget_width in (
        (Vec2(HS_RIGHT_PLAYER_COUNT_WIDGET_X, HS_RIGHT_PLAYER_COUNT_WIDGET_Y), HS_RIGHT_PLAYER_COUNT_WIDGET_W),
        (Vec2(HS_RIGHT_GAME_MODE_WIDGET_X, HS_RIGHT_GAME_MODE_WIDGET_Y), HS_RIGHT_GAME_MODE_WIDGET_W),
        (Vec2(HS_RIGHT_SHOW_SCORES_WIDGET_X, HS_RIGHT_SHOW_SCORES_WIDGET_Y), HS_RIGHT_SHOW_SCORES_WIDGET_W),
        (Vec2(HS_RIGHT_SCORE_LIST_WIDGET_X, HS_RIGHT_SCORE_LIST_WIDGET_Y), HS_RIGHT_SCORE_LIST_WIDGET_W),
    ):
        widget_pos = right_top_left + widget_offset * scale
        w = float(widget_width) * scale
        rl.draw_rectangle(int(widget_pos.x), int(widget_pos.y), int(w), int(widget_h), rl.WHITE)
        rl.draw_rectangle(
            int(widget_pos.x) + 1,
            int(widget_pos.y) + 1,
            max(0, int(w) - 2),
            max(0, int(widget_h) - 2),
            rl.BLACK,
        )

    # Values (static in the oracle).
    player_count = view.state.config.player_count
    if player_count < 1:
        player_count = 1
    if player_count > 4:
        player_count = 4
    player_count_label = f"{player_count} player"
    if player_count != 1:
        player_count_label += "s"
    draw_small_text(
        font,
        player_count_label,
        right_top_left + Vec2(HS_RIGHT_PLAYER_COUNT_VALUE_X * scale, HS_RIGHT_PLAYER_COUNT_VALUE_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Quests",
        right_top_left + Vec2(HS_RIGHT_GAME_MODE_VALUE_X * scale, HS_RIGHT_GAME_MODE_VALUE_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Best of all time",
        right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_VALUE_X * scale, HS_RIGHT_SHOW_SCORES_VALUE_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "default",
        right_top_left + Vec2(HS_RIGHT_SCORE_LIST_VALUE_X * scale, HS_RIGHT_SCORE_LIST_VALUE_Y * scale),
        text_scale,
        text_color,
    )

    drop_off = view._drop_off
    if drop_off is None:
        return
    drop_w = float(drop_off.width) * scale
    drop_h = float(drop_off.height) * scale
    for drop_offset in (
        Vec2(HS_RIGHT_PLAYER_COUNT_DROP_X, HS_RIGHT_PLAYER_COUNT_DROP_Y),
        Vec2(HS_RIGHT_GAME_MODE_DROP_X, HS_RIGHT_GAME_MODE_DROP_Y),
        Vec2(HS_RIGHT_SHOW_SCORES_DROP_X, HS_RIGHT_SHOW_SCORES_DROP_Y),
        Vec2(HS_RIGHT_SCORE_LIST_DROP_X, HS_RIGHT_SCORE_LIST_DROP_Y),
    ):
        drop_pos = right_top_left + drop_offset * scale
        rl.draw_texture_pro(
            drop_off,
            rl.Rectangle(0.0, 0.0, float(drop_off.width), float(drop_off.height)),
            rl.Rectangle(
                drop_pos.x,
                drop_pos.y,
                drop_w,
                drop_h,
            ),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )


def _draw_right_panel_local_score(
    view: "HighScoresView",
    *,
    font: SmallFontData,
    right_top_left: Vec2,
    scale: float,
    highlight_rank: int | None,
) -> None:
    if not view._records:
        return
    idx = int(highlight_rank) if highlight_rank is not None else int(view._scroll_index)
    if idx < 0:
        idx = 0
    if idx >= len(view._records):
        idx = len(view._records) - 1
    entry = view._records[idx]

    text_scale = 1.0 * scale
    text_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.8))
    value_color = rl.Color(int(255 * 0.9), int(255 * 0.9), 255, 255)
    game_time_color = rl.Color(255, 255, 255, int(255 * 0.8))
    lower_section_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.7))
    separator_color = rl.Color(149, 175, 198, int(255 * 0.7))

    name = ""
    try:
        name = str(entry.name())
    except Exception:
        name = ""
    if not name:
        name = "???"
    draw_small_text(
        font,
        name,
        right_top_left + Vec2(HS_LOCAL_NAME_X * scale, HS_LOCAL_NAME_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Local score",
        right_top_left + Vec2(HS_LOCAL_LABEL_X * scale, HS_LOCAL_LABEL_Y * scale),
        text_scale,
        text_color,
    )
    rl.draw_line(
        int(right_top_left.x + 78.0 * scale),
        int(right_top_left.y + 57.0 * scale),
        int(right_top_left.x + 117.0 * scale),
        int(right_top_left.y + 57.0 * scale),
        separator_color,
    )

    date_text = format_score_date(entry)
    if date_text:
        draw_small_text(
            font,
            date_text,
            right_top_left + Vec2(HS_LOCAL_DATE_X * scale, HS_LOCAL_DATE_Y * scale),
            text_scale,
            text_color,
        )
    rl.draw_line(
        int(right_top_left.x + 74.0 * scale),
        int(right_top_left.y + 72.0 * scale),
        int(right_top_left.x + 266.0 * scale),
        int(right_top_left.y + 72.0 * scale),
        separator_color,
    )

    draw_small_text(
        font,
        "Score",
        right_top_left + Vec2(HS_LOCAL_SCORE_LABEL_X * scale, HS_LOCAL_SCORE_LABEL_Y * scale),
        text_scale,
        text_color,
    )
    draw_small_text(
        font,
        "Game time",
        right_top_left + Vec2(HS_LOCAL_TIME_LABEL_X * scale, HS_LOCAL_TIME_LABEL_Y * scale),
        text_scale,
        game_time_color,
    )
    rl.draw_line(
        int(right_top_left.x + 170.0 * scale),
        int(right_top_left.y + 90.0 * scale),
        int(right_top_left.x + 170.0 * scale),
        int(right_top_left.y + 138.0 * scale),
        separator_color,
    )

    score_value = f"{int(getattr(entry, 'score_xp', 0))}"
    draw_small_text(
        font,
        score_value,
        right_top_left + Vec2(HS_LOCAL_SCORE_VALUE_X * scale, HS_LOCAL_SCORE_VALUE_Y * scale),
        text_scale,
        value_color,
    )

    elapsed_ms = int(getattr(entry, "survival_elapsed_ms", 0) or 0)
    _draw_clock_gauge(
        view,
        elapsed_ms=elapsed_ms,
        pos=right_top_left + Vec2(HS_LOCAL_CLOCK_X * scale, HS_LOCAL_CLOCK_Y * scale),
        scale=scale,
    )
    draw_small_text(
        font,
        format_elapsed_mm_ss(elapsed_ms),
        right_top_left + Vec2(HS_LOCAL_TIME_VALUE_X * scale, HS_LOCAL_TIME_VALUE_Y * scale),
        text_scale,
        game_time_color,
    )

    draw_small_text(
        font,
        f"Rank: {ordinal(idx + 1)}",
        right_top_left + Vec2(HS_LOCAL_RANK_X * scale, HS_LOCAL_RANK_Y * scale),
        text_scale,
        text_color,
    )

    frags = int(getattr(entry, "creature_kill_count", 0) or 0)

    shots_fired = int(getattr(entry, "shots_fired", 0) or 0)
    shots_hit = int(getattr(entry, "shots_hit", 0) or 0)
    hit_pct = 0
    if shots_fired > 0:
        hit_pct = int((shots_hit * 100) // shots_fired)
    rl.draw_line(
        int(right_top_left.x + 74.0 * scale),
        int(right_top_left.y + 142.0 * scale),
        int(right_top_left.x + 266.0 * scale),
        int(right_top_left.y + 142.0 * scale),
        separator_color,
    )

    weapon_id = int(getattr(entry, "most_used_weapon_id", 0) or 0)
    weapon_name, icon_index = _weapon_label_and_icon(view, weapon_id)
    if icon_index is not None:
        _draw_wicon(
            view,
            icon_index,
            pos=right_top_left + Vec2(HS_LOCAL_WICON_X * scale, HS_LOCAL_WICON_Y * scale),
            scale=scale,
        )
    weapon_name_x = HS_LOCAL_WICON_X * scale + max(
        0.0,
        32.0 * scale - measure_small_text_width(font, weapon_name, text_scale) * 0.5,
    )
    draw_small_text(
        font,
        weapon_name,
        right_top_left + Vec2(weapon_name_x, HS_LOCAL_WEAPON_Y * scale),
        text_scale,
        lower_section_color,
    )
    draw_small_text(
        font,
        f"Frags: {frags}",
        right_top_left + Vec2(HS_LOCAL_FRAGS_X * scale, HS_LOCAL_FRAGS_Y * scale),
        text_scale,
        lower_section_color,
    )
    draw_small_text(
        font,
        f"Hit %: {hit_pct}%",
        right_top_left + Vec2(HS_LOCAL_HIT_X * scale, HS_LOCAL_HIT_Y * scale),
        text_scale,
        lower_section_color,
    )
    rl.draw_line(
        int(right_top_left.x + 74.0 * scale),
        int(right_top_left.y + 194.0 * scale),
        int(right_top_left.x + 266.0 * scale),
        int(right_top_left.y + 194.0 * scale),
        separator_color,
    )


def _draw_clock_gauge(
    view: "HighScoresView",
    *,
    elapsed_ms: int,
    pos: Vec2,
    scale: float,
) -> None:
    table_tex = view._clock_table_tex
    pointer_tex = view._clock_pointer_tex
    if table_tex is None or pointer_tex is None:
        return
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
    view: "HighScoresView",
    icon_index: int,
    *,
    pos: Vec2,
    scale: float,
) -> None:
    tex = view._wicons_tex
    if tex is None:
        return
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


def _weapon_label_and_icon(view: "HighScoresView", weapon_id: int) -> tuple[str, int | None]:
    from ...weapons import WEAPON_BY_ID, weapon_display_name

    weapon = WEAPON_BY_ID.get(int(weapon_id))
    if weapon is None:
        return f"Weapon {int(weapon_id)}", None
    name = weapon_display_name(int(weapon.weapon_id), preserve_bugs=bool(view.state.preserve_bugs))
    return name, weapon.icon_index


__all__ = ["draw_right_panel"]
