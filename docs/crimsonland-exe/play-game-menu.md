---
tags:
  - status-analysis
---

# Play Game menu (state 1)

This page documents the classic Crimsonland.exe **Play Game** panel (game state
`1`), updated by `sub_44ed80`.

The screen is a mode selector with:

- Mode buttons: Quests / Rush / Survival / (Typ-o-Shooter gated) / Tutorial
- Player count dropdown (1..4 players)
- Hover tooltips for each mode
- Optional F1 overlay showing "times played" counters

## Panel positions (from `ui_menu_layout_init`)

- Panel: `(-45, 210)`
- Back button: `(-55, 462)`

See also: `docs/crimsonland-exe/main-menu.md` (panel animation + widescreen shift).

## Content anchor coordinates (from `sub_44ed80`)

Inside the panel, `sub_44ed80` computes a base point:

- `base_x = panel_left + 266` (i.e. `330 - 64`)
- `base_y = panel_top + 50`

All child widgets are positioned relative to this.

## Player count dropdown (from `ui_list_widget_update @ 0x0043efc0`)

`sub_44ed80` places the dropdown at:

- `x = base_x + 80`
- `y = base_y + 1`

`ui_list_widget_update` layout constants:

- Width: `max(label_width) + 0x30` (48px)
- Header height: `16px`
- Open height: `(count * 16) + 0x18` (24px)
- Arrow icon: `16x16` at `(x + width - 16 - 1, y)`
- Selected label text: `(x + 4, y + 1)`
- List row `i` text: `(x + 4, y + 17 + i * 16)`

Text color/alpha (`grim->set_color_rgba` via vtable +0x114):

- Header label: alpha `0x3f733333` (~0.95) when idle; alpha `0x3f400000` (0.75) when "active"
- Row labels: base alpha `0x3f333333` (0.70); hovered alpha `0x3f733333` (~0.95)
- Selected row can use alpha `0x3f75c28f` (~0.96) when focused

## Mode list ordering and spacing (from `sub_44ed80`)

### Mode list X

All mode buttons use `x = base_x`.

### Vertical spacing regimes

There are two spacing regimes chosen by:

```
if (quest_unlock_index < 0x28) or (player_count > 1):
    # roomy layout
else:
    # tight layout
```

Roomy layout:

- First button `y = base_y + 32`
- Step `+32` per row

Tight layout:

- First button `y = base_y + 26`
- Step `+28` per row

### Tutorial placement

Tutorial is only shown when `player_count == 1`.

`sub_44ed80` places it at the top when it thinks no relevant modes have been
played yet (it uses a cheap counter check), otherwise it appends it after the
main modes.

### Typ-o-Shooter gating

Typ-o-Shooter is only offered in the tight layout, and only when:

- `game_is_full_version() != 0`
- `player_count == 1`

## Button text rendering (from `ui_button_update @ 0x0043e830`)

`ui_button_update` selects `ui_buttonSm` vs `ui_buttonMd` based on label width.

Label placement and color:

- Text color is **white**; alpha is ~1.0 hovered and ~0.7 when not hovered.
- X is centered with a `+1` pixel nudge.
- Y is `button_y + 10` (not perfectly centered).

## Tooltip positions (from `sub_44ed80`)

`sub_44ed80` subtracts `55` from the base X and anchors tooltips below the mode list:

- `tooltip_x = base_x - 55`
- `tooltip_y = y_after_last_button + 16`

Per-mode offsets (added to `tooltip_x/tooltip_y`):

- Quests: `x - 8`
- Rush: `x + 32`
- Survival: `x + 20`
- Typ-o: `y - 12` (no X offset)
- Tutorial: `x + 38`

Tooltip alpha uses a per-mode hover timer scaled by `0.000900000043` (clamped to 1.0).

## "Times played" overlay (from `sub_44ed80`)

Holding `F1` (DIK `0x3B`) draws:

- `"times played:"` at `(base_x + 132, base_y + 16)`
- Per-mode numbers at `x = base_x + 158` and `y = (button_y + 8)`

Counts come from `game.cfg`:

- Quests total: sum of 40 ints from `game_status_blob+0x104..0x1a4`
- Rush: `mode_play_rush`
- Survival: `mode_play_survival`
- Typ-o: `mode_play_typo`
