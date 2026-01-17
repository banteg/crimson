# Game mode map

Observed values for `_DAT_00480360` (game mode selector) from the decompiled `crimsonland.exe`.

| Value | Mode | Evidence |
| --- | --- | --- |
| 1 | Survival | Mode select button labeled `Survival` sets `_DAT_00480360 = 1`. |
| 2 | Rush | Mode select button labeled `Rush` sets `_DAT_00480360 = 2`. |
| 3 | Quests | `FUN_00412960` returns the `Quests` label when `_DAT_00480360 == 3`. |
| 4 | Typ-o-Shooter | Mode select button labeled `Typ-o-Shooter` sets `_DAT_00480360 = 4`. |
| 8 | Unknown (special mode) | Skips some perk/UI logic, forces a preset perk list, and calls `FUN_00408990` in the main loop. No direct UI label assignment seen yet. |

Notes:
- Values 1/2/4 are set in the mode select UI handler (see the block around `FUN_00403430`).
- Value 3 appears in the mode label helper (`FUN_00412960`) and gating logic in perk selection.
- Value 8 is referenced in perk selection and update logic but is not assigned in the UI code seen so far.
