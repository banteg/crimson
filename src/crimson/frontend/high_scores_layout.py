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

# Buttons inside the left panel (relative to the left panel top-left).
HS_BUTTON_X = 234.0  # x0=136 at 1024x768
HS_BUTTON_Y0 = 268.0  # y0=462
HS_BUTTON_STEP_Y = 33.0

HS_BACK_BUTTON_X = 400.0  # x0=302
HS_BACK_BUTTON_Y = 301.0  # y0=495
