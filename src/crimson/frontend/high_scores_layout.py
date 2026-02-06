"""
Layout constants for the classic high scores screen (state_id=14).

Measured from analysis/frida/ui_render_trace_oracle_1024x768.json.
"""

from __future__ import annotations

# Panel positions are expressed in "panel pos" (pre-offset) space, matching other menu panels:
#   panel_top_left = (panel_pos_x + MENU_PANEL_OFFSET_X, panel_pos_y + y_shift + MENU_PANEL_OFFSET_Y)

HS_LEFT_PANEL_POS_X = -119.0
HS_LEFT_PANEL_POS_Y = 185.0
HS_LEFT_PANEL_HEIGHT = 378.0

HS_RIGHT_PANEL_POS_X = 609.0
HS_RIGHT_PANEL_POS_Y = 200.0
HS_RIGHT_PANEL_HEIGHT = 254.0


def hs_right_panel_pos_x(screen_width: float) -> float:
    """
    Return the classic right-panel base X for high-scores/databases screens.

    Modeled from `ui_menu_layout_init` (`sub_450190`) writes to `data_48a110`:
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

# Closed dropdown widgets (borders + value text + arrow icon).
HS_RIGHT_PLAYER_COUNT_WIDGET_X = 46.0  # x=676
HS_RIGHT_PLAYER_COUNT_WIDGET_Y = 78.0  # y=287
HS_RIGHT_PLAYER_COUNT_WIDGET_W = 102.0
HS_RIGHT_PLAYER_COUNT_VALUE_X = 50.0  # "1 player" at (680,288)
HS_RIGHT_PLAYER_COUNT_VALUE_Y = 79.0
HS_RIGHT_PLAYER_COUNT_DROP_X = 131.0  # ui_dropOff bbox [761,287]..[777,303]
HS_RIGHT_PLAYER_COUNT_DROP_Y = 78.0

HS_RIGHT_GAME_MODE_WIDGET_X = 174.0  # x=804
HS_RIGHT_GAME_MODE_WIDGET_Y = 78.0  # y=287
HS_RIGHT_GAME_MODE_WIDGET_W = 95.0
HS_RIGHT_GAME_MODE_VALUE_X = 178.0  # "Quests" at (808,288)
HS_RIGHT_GAME_MODE_VALUE_Y = 79.0
HS_RIGHT_GAME_MODE_DROP_X = 252.0  # ui_dropOff bbox [882,287]..[898,303]
HS_RIGHT_GAME_MODE_DROP_Y = 78.0

HS_RIGHT_SHOW_SCORES_WIDGET_X = 44.0  # x=674
HS_RIGHT_SHOW_SCORES_WIDGET_Y = 120.0  # y=329
HS_RIGHT_SHOW_SCORES_WIDGET_W = 134.0
HS_RIGHT_SHOW_SCORES_VALUE_X = 48.0  # "Best of all time" at (678,330)
HS_RIGHT_SHOW_SCORES_VALUE_Y = 121.0
HS_RIGHT_SHOW_SCORES_DROP_X = 161.0  # ui_dropOff bbox [791,329]..[807,345]
HS_RIGHT_SHOW_SCORES_DROP_Y = 120.0

HS_RIGHT_SCORE_LIST_WIDGET_X = 44.0  # x=674
HS_RIGHT_SCORE_LIST_WIDGET_Y = 164.0  # y=373
HS_RIGHT_SCORE_LIST_WIDGET_W = 174.0
HS_RIGHT_SCORE_LIST_VALUE_X = 48.0  # "default" at (678,374)
HS_RIGHT_SCORE_LIST_VALUE_Y = 165.0
HS_RIGHT_SCORE_LIST_DROP_X = 201.0  # ui_dropOff bbox [831,373]..[847,389]
HS_RIGHT_SCORE_LIST_DROP_Y = 164.0

# Right panel (Survival): local score details + weapon icon.
HS_LOCAL_NAME_X = 78.0  # "banteg" at (708,253)
HS_LOCAL_NAME_Y = 44.0
HS_LOCAL_LABEL_X = 78.0  # "Local score" at (708,267)
HS_LOCAL_LABEL_Y = 58.0
HS_LOCAL_DATE_X = 193.0  # "31. Jan 2026" at (823,281)
HS_LOCAL_DATE_Y = 72.0
HS_LOCAL_SCORE_LABEL_X = 105.0  # "Score" at (735,299)
HS_LOCAL_SCORE_LABEL_Y = 90.0
HS_LOCAL_TIME_LABEL_X = 192.0  # "Game time" at (822,299)
HS_LOCAL_TIME_LABEL_Y = 90.0
HS_LOCAL_SCORE_VALUE_X = 105.0  # "27874" at (735,314)
HS_LOCAL_SCORE_VALUE_Y = 105.0
HS_LOCAL_TIME_VALUE_X = 226.0  # "3:28" at (856,318)
HS_LOCAL_TIME_VALUE_Y = 109.0
HS_LOCAL_RANK_X = 94.0  # "Rank: 2nd" at (724,329)
HS_LOCAL_RANK_Y = 120.0
HS_LOCAL_WICON_X = 90.0  # ui_wicons bbox [720,355]..[784,387]
HS_LOCAL_WICON_Y = 146.0
HS_LOCAL_FRAGS_X = 200.0  # "Frags: 441" at (830,356)
HS_LOCAL_FRAGS_Y = 147.0
HS_LOCAL_HIT_X = 200.0  # "Hit %: 64%" at (830,370)
HS_LOCAL_HIT_Y = 161.0
HS_LOCAL_WEAPON_X = 90.0  # "Sawed-off Shotgun" at (720,387)
HS_LOCAL_WEAPON_Y = 178.0
