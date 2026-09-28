from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from ..game_modes import GameMode
from ..game_states import GameStateId
from ..persistence.highscores import HighScoreRecord
from ..weapons import WEAPON_BY_ID, weapon_display_name
from .formatting import format_ordinal, highscore_format_date_label
from .hud import weapon_icon_src

# `render_tint_color` as initialized by `render_tint_color_global_init`.
_RENDER_TINT_RGB = (0.58431375, 0.686274529, 0.776470602)
_RESULT_STATES = (GameStateId.GAME_OVER, GameStateId.QUEST_RESULTS, GameStateId.QUEST_FAILED)


class _StatsHover(msgspec.Struct):
    """Native `ui_stats_hover_weapon` / `ui_stats_hover_time` / `ui_stats_hover_hit_ratio` globals."""

    weapon: float = 0.0
    time: float = 0.0
    hit_ratio: float = 0.0


_hover = _StatsHover()


def _half_width(font: SmallFontData, text: str) -> int:
    # Native divides the int text width by 2 with C integer division.
    return int(measure_small_text_width(font, text)) // 2


def _divider(pos: Vec2, width: float, height: float, color: rl.Color) -> None:
    # `grim_draw_rect_outline` with a 1px side is one filled quad.
    rl.draw_rectangle_rec(rl.Rectangle(pos.x - 16.0, pos.y, width, height), color)


def ui_draw_clock_gauge(resources: RuntimeResources, x: int, y: int, time_ms: int, alpha: float) -> None:
    tint = grim_color(1.0, 1.0, 1.0, alpha)
    table = resources.texture(TextureId.UI_CLOCK_TABLE)
    rl.draw_texture_pro(
        table,
        rl.Rectangle(0.0, 0.0, float(table.width), float(table.height)),
        rl.Rectangle(float(x), float(y), 32.0, 32.0),
        rl.Vector2(0.0, 0.0),
        0.0,
        tint,
    )
    # The pointer quad rotates about its center by (time_ms / 1000) * 6 degrees.
    pointer = resources.texture(TextureId.UI_CLOCK_POINTER)
    rl.draw_texture_pro(
        pointer,
        rl.Rectangle(0.0, 0.0, float(pointer.width), float(pointer.height)),
        rl.Rectangle(float(x) + 16.0, float(y) + 16.0, 32.0, 32.0),
        rl.Vector2(16.0, 16.0),
        float(int(time_ms) // 1000) * 6.0,
        tint,
    )


def ui_text_input_render(
    xy: Vec2,
    record: HighScoreRecord,
    alpha: float,
    rank: int,
    *,
    game_state: GameStateId,
    ui_phase: int,
    resources: RuntimeResources,
    mouse: rl.Vector2,
    dt: float,
) -> None:
    """Draw the high-score card shared by game over, quest results/failed and the high-score screen."""
    font = resources.small_font
    divider_color = grim_color(*_RENDER_TINT_RGB, alpha * 0.7)
    label_color = grim_color(0.9, 0.9, 0.9, alpha * 0.8)
    tooltip_color = grim_color(0.9, 0.9, 0.9, alpha * 0.7)
    hover_step = dt + dt
    results = game_state in _RESULT_STATES
    pos = Vec2(xy.x + 4.0, xy.y)

    if not results:
        name = record.name()
        draw_small_text(font, name, pos, grim_color(1.0, 1.0, 1.0, alpha))
        rl.draw_rectangle_rec(
            rl.Rectangle(pos.x, pos.y + 13.0, float(int(measure_small_text_width(font, name))), 1.0),
            divider_color,
        )
        if record.flags & 2:
            draw_small_text(
                font, "Internet score of local origin", pos.offset(dy=14.0), grim_color(0.8, 0.8, 0.8, alpha * 0.8),
            )
            draw_small_text(
                font, f"uni#{record.uni_num}", pos + Vec2(94.0, -12.0), grim_color(0.5, 0.5, 0.5, alpha * 0.5),
            )
        elif record.flags & 1:
            draw_small_text(font, "Score from the Internet", pos.offset(dy=14.0), grim_color(0.7, 1.0, 0.7, alpha * 0.8))
        else:
            draw_small_text(font, "Local score", pos.offset(dy=14.0), grim_color(0.8, 0.8, 0.8, alpha * 0.8))

        pos = pos.offset(dy=15.0)
        date = highscore_format_date_label(record.day, record.month, record.year_offset + 2000)
        draw_small_text(
            font, date, Vec2(pos.x + 192.0 - 32.0 - 8.0 - _half_width(font, date), pos.y + 13.0), label_color,
        )
        pos = Vec2(xy.x + 16.0, pos.y + 13.0)
        _divider(pos, 192.0, 1.0, divider_color)
        pos = pos.offset(dy=4.0 + 14.0)

    draw_small_text(font, "Score", Vec2(pos.x + 32.0 - _half_width(font, "Score"), pos.y), label_color)
    match record.game_mode_id:
        case GameMode.RUSH | GameMode.QUESTS:
            score_text = f"{float(int(record.survival_elapsed_ms)) * 0.001:.2f} secs"
        case _:
            score_text = f"{record.score_xp}"
    draw_small_text(
        font,
        score_text,
        Vec2(pos.x + 32.0 - _half_width(font, score_text), pos.y + 15.0),
        grim_color(0.9, 0.9, 1.0, alpha),
    )
    if game_state != GameStateId.QUEST_FAILED:
        rank_text = f"Rank: {format_ordinal(rank)}"
        draw_small_text(font, rank_text, Vec2(pos.x + 32.0 - _half_width(font, rank_text), pos.y + 30.0), label_color)

    pos = pos.offset(dx=96.0)
    # The vertical divider leaves its color current for the next label.
    _divider(pos, 1.0, 48.0, divider_color)
    if record.game_mode_id == GameMode.QUESTS:
        draw_small_text(font, "Experience", pos, divider_color)
        xp_text = f"{record.score_xp}"
        draw_small_text(font, xp_text, Vec2(pos.x + 32.0 - _half_width(font, xp_text), pos.y + 15.0), label_color)
        _hover.time -= hover_step
    else:
        draw_small_text(font, "Game time", pos.offset(dx=6.0), divider_color)
        ui_draw_clock_gauge(resources, int(pos.x + 8.0), int(pos.y + 13.0), record.survival_elapsed_ms, alpha)
        inside = pos.x + 8.0 < mouse.x < pos.x + 72.0 and pos.y + 16.0 < mouse.y < pos.y + 45.0
        _hover.time += hover_step if inside else -hover_step
        seconds = int(record.survival_elapsed_ms) // 1000
        draw_small_text(font, f"{seconds // 60}:{seconds % 60:02d}", pos + Vec2(40.0, 19.0), label_color)

    pos = Vec2(pos.x - 96.0, pos.y + 52.0)
    hide_weapon_row = (ui_phase == 2 and game_state == GameStateId.QUEST_RESULTS) or (results and ui_phase == 0)
    if not hide_weapon_row:
        _divider(pos, 192.0, 1.0, divider_color)
        pos = pos.offset(dy=4.0)
        weapon = WEAPON_BY_ID[record.most_used_weapon_id]
        wicons = resources.texture(TextureId.UI_WICONS)
        rl.draw_texture_pro(
            wicons,
            weapon_icon_src(wicons, weapon.icon_index),
            rl.Rectangle(float(int(pos.x)), float(int(pos.y)), 64.0, 32.0),
            rl.Vector2(0.0, 0.0),
            0.0,
            grim_color(1.0, 1.0, 1.0, alpha),
        )
        inside = pos.x < mouse.x < pos.x + 64.0 and pos.y < mouse.y < pos.y + 32.0
        _hover.weapon += hover_step if inside else -hover_step

        weapon_name = weapon_display_name(weapon.weapon_id)
        name_x = max(0.0, float(32 - _half_width(font, weapon_name)))
        draw_small_text(font, weapon_name, Vec2(pos.x + name_x, pos.y + 32.0), tooltip_color)
        draw_small_text(font, f"Frags: {record.creature_kill_count}", pos + Vec2(110.0, 1.0), tooltip_color)
        # Native divides by zero shots into INT_MIN; the port shows 0%.
        hit_pct = int(record.shots_hit * 100.0 / record.shots_fired) if record.shots_fired > 0 else 0
        draw_small_text(font, f"Hit %: {hit_pct}%", pos + Vec2(110.0, 15.0), tooltip_color)
        inside = pos.x + 110.0 < mouse.x < pos.x + 174.0 and pos.y + 15.0 < mouse.y < pos.y + 32.0
        _hover.hit_ratio += hover_step if inside else -hover_step
        pos = pos.offset(dy=48.0)
    else:
        _hover.hit_ratio = 0.0

    _divider(pos, 192.0, 1.0, divider_color)
    pos = pos.offset(dy=4.0)
    _hover.weapon = clamp(_hover.weapon, 0.0, 1.0)
    _hover.time = clamp(_hover.time, 0.0, 1.0)
    _hover.hit_ratio = clamp(_hover.hit_ratio, 0.0, 1.0)

    if results:
        for hover, dx, text in (
            (_hover.weapon, -20.0, "Most used weapon during the game"),
            (_hover.time, 12.0, "The time the game lasted"),
            (_hover.hit_ratio, -22.0, "The % of shot bullets hit the target"),
        ):
            if hover > 0.5:
                draw_small_text(font, text, pos.offset(dx=dx), grim_color(0.9, 0.9, 0.9, (hover - 0.5) * alpha * 2.0))
