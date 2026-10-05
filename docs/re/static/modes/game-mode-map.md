---
tags:
  - status-analysis
---

# Game mode map

Values of `config_game_mode` (game mode selector), declared as the
`GAME_MODE_*` enum in `third_party/headers/crimsonland_types.h`.

| Value | Mode | Evidence |
| --- | --- | --- |
| 1 | Survival | The Play Game menu's `Survival` button sets `GAME_MODE_SURVIVAL`. |
| 2 | Rush | The Play Game menu's `Rush` button sets `GAME_MODE_RUSH`. |
| 3 | Quests | Starting a quest from the quest select menu sets `GAME_MODE_QUEST`; `game_mode_label` (`0x00412960`) returns the `Quests` label. |
| 4 | Typ-o-Shooter | The Play Game menu's `Typ-o-Shooter` button sets `GAME_MODE_TYPO_SHOOTER`. |
| 8 | Tutorial | The Play Game menu's `Tutorial` button sets `GAME_MODE_TUTORIAL`. Calls `tutorial_timeline_update` in the main loop, forces a preset perk list, and uses the tutorial prompt/strings. |

Notes:

- The mode-select assignments of 1/2/4/8 are in `decomp/1.9/crimsonland/menus/play_game_menu_update.cpp`.
- Value 3 is assigned in `decomp/1.9/crimsonland/menus/quest_select_menu_update.cpp`.
- Demo mode (`demo_mode_start`), the victory screen and the statistics menu
  also set the mode directly.
