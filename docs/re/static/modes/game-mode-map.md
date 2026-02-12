---
tags:
  - status-analysis
---

# Game mode map

Observed values for `_DAT_00480360` (game mode selector) from the decompiled `crimsonland.exe`.

| Value | Mode | Evidence |
| --- | --- | --- |
| 1 | Survival | Mode select button labeled `Survival` sets `_DAT_00480360 = 1`. |
| 2 | Rush | Mode select button labeled `Rush` sets `_DAT_00480360 = 2`. |
| 3 | Quests | `game_mode_label` (`FUN_00412960`) returns the `Quests` label when `_DAT_00480360 == 3`. |
| 4 | Typ-o-Shooter | Mode select button labeled `Typ-o-Shooter` sets `_DAT_00480360 = 4`. |
| 8 | Tutorial (hidden) | Calls `tutorial_timeline_update` in the main loop, forces a preset perk list, and uses the tutorial prompt/strings; not exposed in the mode select UI. |

Notes:

- Values 1/2/4 are set in the mode select UI handler (see the block around `ui_mouse_inside_rect_with_padding`).
- Value 3 appears in the mode label helper (`game_mode_label` / `FUN_00412960`) and gating logic in perk selection.
- Value 8 is referenced in perk selection and update logic but is not assigned in the UI code seen so far.
