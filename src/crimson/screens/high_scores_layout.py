"""
Layout constants for the classic high scores screen (state_id=14).

Measured from analysis/frida/ui_render_trace_oracle_1024x768.json.
"""

from __future__ import annotations

from grim.geom import Vec2

# Panel positions are expressed in "panel pos" (pre-offset) space, matching other menu panels:
#   panel_top_left = (panel_pos_x + MENU_PANEL_OFFSET_X, panel_pos_y + y_shift + MENU_PANEL_OFFSET_Y)

HS_LEFT_PANEL_POS_X = -119.0
HS_LEFT_PANEL_POS_Y = 185.0
HS_LEFT_PANEL_HEIGHT = 378.0

HS_RIGHT_PANEL_POS_X = 609.0
HS_RIGHT_PANEL_POS_Y = 200.0
HS_RIGHT_PANEL_HEIGHT = 254.0


def hs_left_panel_pos_x(screen_width: float) -> float:
    """
    Return left-panel base X for state 14/15/16.

    Native callbacks keep the regular x at widths above 640 and shift the
    whole left stack 50px left in 640-wide mode.
    """

    if int(screen_width) <= 640:
        return HS_LEFT_PANEL_POS_X - 50.0
    return HS_LEFT_PANEL_POS_X


def hs_right_panel_pos_x(screen_width: float) -> float:
    """
    Return the classic right-panel base X for high-scores/databases screens.

    Modeled from `ui_menu_layout_init` writes to `data_48a110`:
      x = screen_width - 350
      if screen_width <= 800:
          x += 10  (<=640)  or  x -= 30  (641..800)
      else:
          x -= 65

    At 1024 this resolves to 609 (our original constant).
    """

    w = int(screen_width)
    x = float(w - 350)
    if w <= 800:
        if w <= 640:
            x += 10.0
        else:
            x -= 30.0
    else:
        x -= 65.0
    return x


def hs_right_options_x_shift(screen_width: float) -> float:
    """
    Additional right-panel options-column X shift in highscore state (14).

    `highscore_screen_update` nudges this block by +10 at 640 width.
    """

    if int(screen_width) <= 640:
        return 10.0
    return 0.0


def hs_right_local_card_x_shift(screen_width: float) -> float:
    """
    Additional right-panel local-score card X shift in highscore state (14).

    Capture-backed effective offset at 640 width.
    """

    if int(screen_width) <= 640:
        return 12.0
    return 0.0


def weapons_db_right_detail_x_shift(screen_width: float) -> float:
    """
    Additional right-panel detail X shift in weapons DB state (15).

    `unlocked_weapons_database_update` adds +20 at 640 width.
    """

    if int(screen_width) <= 640:
        return 20.0
    return 0.0


def perks_db_right_detail_x_shift(screen_width: float) -> float:
    """
    Additional right-panel detail X shift in perks DB state (16).

    `unlocked_perks_database_update` subtracts 10 at 640 width.
    """

    if int(screen_width) <= 640:
        return -10.0
    return 0.0

# Buttons inside the left panel (relative to the left panel top-left).
HS_BUTTON_X = 234.0  # x0=136 at 1024x768
HS_BUTTON_Y0 = 268.0  # y0=462
HS_BUTTON_STEP_Y = 33.0

HS_BACK_BUTTON_X = 400.0  # x0=302
HS_BACK_BUTTON_Y = 301.0  # y0=495

# Underline under "High scores - ..." title.
# state_14 quests: [171,249]..[294,250], survival: [168,249]..[297,250]
HS_TITLE_UNDERLINE_X = 269.0
HS_TITLE_UNDERLINE_Y = 55.0
HS_TITLE_UNDERLINE_W = 123.0

# Left score-list frame (white border + black fill).
# state_14: [112,295]..[362,459] and inner [113,296]..[361,458]
HS_SCORE_FRAME_X = 210.0
HS_SCORE_FRAME_Y = 101.0
HS_SCORE_FRAME_W = 250.0
HS_SCORE_FRAME_H = 164.0

# Quest-mode high score selector arrow (left panel).
# state_14:High scores - Quests: ui_arrow.jaz bbox [351,256]..[383,272]
# left panel top-left at 1024x768 is (-98,194).
HS_QUEST_ARROW_X = 449.0
HS_QUEST_ARROW_Y = 62.0
# Native `highscore_screen` puts the Hardcore checkbox at the column header origin (Rank - 9) + (162, -2).
HS_HARDCORE_CHECKBOX_OFFSET = Vec2(364.0, 82.0)

# Right panel (Quests): options + dropdown widgets.
# right panel top-left at 1024x768 is (630,209).
HS_RIGHT_CHECK_X = 44.0  # ui_checkOn bbox [674,253]..[690,269]
HS_RIGHT_CHECK_Y = 44.0
HS_RIGHT_SHOW_INTERNET_X = 66.0  # "Show internet scores" at (696,254)
HS_RIGHT_SHOW_INTERNET_Y = 45.0

HS_RIGHT_NUMBER_PLAYERS_X = 46.0  # "Number of players" at (676,273)
HS_RIGHT_NUMBER_PLAYERS_Y = 64.0
HS_RIGHT_GAME_MODE_X = 174.0  # "Game mode" at (804,273)
HS_RIGHT_GAME_MODE_Y = 64.0
HS_RIGHT_SHOW_SCORES_X = 44.0  # "Show scores:" at (674,315)
HS_RIGHT_SHOW_SCORES_Y = 106.0
HS_RIGHT_SCORE_LIST_X = 44.0  # "Selected score list:" at (674,359)
HS_RIGHT_SCORE_LIST_Y = 150.0

# `ui_list_widget_update` origins; each list sizes itself from its items.
HS_RIGHT_PLAYER_COUNT_WIDGET = Vec2(46.0, 78.0)  # (676,287)
HS_RIGHT_GAME_MODE_WIDGET = Vec2(174.0, 78.0)  # (804,287)
HS_RIGHT_SHOW_SCORES_WIDGET = Vec2(44.0, 120.0)  # (674,329)
HS_RIGHT_SCORE_LIST_WIDGET = Vec2(44.0, 164.0)  # (674,373)
