---
tags:
  - status-analysis
---

# Quest select menu (state 0x0b)

This page documents the classic Crimsonland.exe **Quest selection** screen
(transition target `0x0b`), updated by `quest_select_menu_update`.

The screen lets the player:

- pick a quest stage (1..5)
- pick a quest within that stage (1..10)
- toggle Hardcore after reaching stage 5 (unlock index >= 40)
- optionally display per-quest completion stats with `F1`

## Anchor coordinates (from `quest_select_menu_update`)

The function builds its layout from two base sums:

- `x_sum = data_48e22c + data_48e208`
- `y_sum = data_48e20c + data_48e230`

From these, it positions the title texture:

- `title_x = x_sum + 300 + data_48e1f8 + 64 - 145` (i.e. `+219` plus an extra offset)
- `title_y = y_sum + 40 + 4` (i.e. `+44`)
- size: `64x32` (drawn from `ui_textQuest`)

## Stage icons (from `ui_num1..ui_num5`)

- start: `icons_x0 = title_x + 64 + 16` (i.e. `title_x + 80`)
- y: `icons_y = title_y + 3`
- step: `+36` per icon
- base size: `32x32`
- scale: `1.0` for the current stage, `0.8` otherwise

Input:

- click an icon to select that stage
- left/right keys: DIK_LEFT `0xCB` decrements stage, DIK_RIGHT `0xCD` increments stage (clamped 1..5)

Hover bounds are a fixed `32x32` anchored at `(icon_x, title_y)` (note: `title_y`, not `icons_y`).

## Quest list (10 rows)

The list is derived from the last icon X:

- `last_icon_x = icons_x0 + 36 * 4`
- `list_x = last_icon_x - 208 + 16`
- `list_y0 = title_y + 50`
- row step: `+20`

Row text:

- number: `"%d.%d"` at `(list_x, row_y)` where `row_y = list_y0 + row * 20`
- name: at `(list_x + 32, row_y)`
  - unlocked: quest title from the quest metadata table
  - locked: `"???"` (string at `0x00478884`)

Hover/click rect per row:

- left: `list_x - 10`
- top: `row_y - 2`
- right: `list_x + 210`
- bottom: `row_y + 18`

Unlock gating:

- global quest index: `(stage - 1) * 10 + row`
- normal: unlocked if `quest_unlock_index >= global_index`
- hardcore: unlocked if `quest_unlock_index_full >= global_index`

## Hardcore toggle (after unlock >= 40)

Hardcore is only shown once `quest_unlock_index >= 0x28` (40).

Position:

- checkbox x: `list_x + 132`
- checkbox y: `list_y0 - 12`

After the checkbox update, the list start is pushed down by `+10`:

- `list_y0 += 10`

The flag is stored in `crimson.cfg` at offset `0x448` (`hardcore_flag`) and is forcibly cleared when
`game_is_full_version() == 0`.

## `F1` stats: `(completed/games)`

Holding `F1` (DIK_F1 `0x3B`) draws:

- header `(completed/games)` at `(list_x + 96, y_after_list - 2)`
- per unlocked quest row: `(%d/%d)` appended after the quest title

Values are read from `game.cfg` (the in-memory `game_status_blob`) using an index:

- `idx = row + stage * 10`
- games: `game_status_blob + 0xDC + idx * 4`
- completed: `game_status_blob + 0x17C + idx * 4`

Note: the stage-5 indices do not fit cleanly in the 0x268-byte saved blob; this likely implies either
a missing/incorrectly-sized stats region in the classic build, or that the stats are only meaningful
for stages 1..4.

## Back button

A UI button (`ui_button_update`) labeled `"Back"` returns to the Play Game menu (state `1`):

- x: `list_x + 148`
- y: `y_after_list + 12`
