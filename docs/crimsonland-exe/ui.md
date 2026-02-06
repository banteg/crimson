---
tags:
  - status-analysis
---

# UI and menus
This page groups UI element logic, menu loops, and transition helpers.

## UI element timeline (ui_elements_update_and_render / FUN_0041a530)

Responsibilities:

- Updates the global transition timeline `ui_elements_timeline` (`DAT_00487248`) using `DAT_00480844`.
  Direction is controlled by `ui_transition_direction` (`DAT_0048724c`) (0 = countdown, nonzero = count up).

- When the timeline goes below zero, it calls `game_state_set` (`FUN_004461c0`) with `game_state_pending` (`DAT_00487274`) to
  switch state and then sets `game_state_pending` (`DAT_00487274`) = `0x19` (idle).

- Clamps the timeline to the maximum active element value
  (`ui_elements_max_timeline`).

- Iterates the UI element pointer table (`0x0048f168 .. 0x0048f20b`, 41 pointers)
  **in reverse order** (from `ui_element_table_start` down to
  `ui_element_table_end`), calling `ui_element_update` (`FUN_00446900`) and
  `ui_element_render` for each entry.

Helpers:

- `ui_elements_reset_state` (`FUN_00446170`) clears element active flags,
  hover timers, and per-element callbacks (`on_activate` / `on_update`).

- `ui_elements_max_timeline` (`FUN_00446190`) returns the max timeline value
  among active elements.

## Recovered menu init bitfields

Recent data-map lifts for one-shot setup guards:

- `menu_item_palette_init_flags` (`0x004cc910`): `ui_menu_item_update` static
  color palette init (idle/hover RGBA blocks).
- `statistics_menu_init_flags` (`0x004d0f20`): `statistics_menu_update`
  tab/button setup guards (High scores, Weapons, Perks, Credits, Typ-o, Mods,
  Check for updates, Back).
- `profile_menu_init_flags` (`0x004cccd8`): `ui_profile_menu_update` setup
  guards for profile text input, action buttons, and list widget wiring.
- `credits_screen_init_flags` (`0x00480978`): `credits_screen_update` one-shot
  setup guards for Back and Secret buttons.
- `mods_menu_init_flags` (`0x00481bb8`): `mods_menu_update` one-shot setup
  guards for list widget and action buttons.

## Menu UI loop (perk_selection_screen_update)

A common menu loop that:

1) Calls the gameplay render pass (`gameplay_render_world`, `FUN_00405960`).
2) Runs `ui_elements_update_and_render`.
3) Draws menu content and buttons (`ui_button_update`).

### TODO (runtime)

Perk selection does **not** fade the world; it keeps the gameplay render pass and overlays active.

- `perk_selection_screen_update` calls `gameplay_render_world` but does **not** call `hud_update_and_render`, so the HUD
  disappears immediately when entering state `6`.
- `gameplay_render_world` forces `ui_transition_alpha = 1.0` for `game_state_id == 6` (perk selection) and `== 9`
  (gameplay), so the usual `ui_transition_alpha` gates in `player_render_overlays` / `creature_render_all` /
  `projectile_render` / `bonus_render` do not hide those layers during perk selection.
- The perk menu panel slides using the UI element timeline (`ui_elements_timeline`) and `ui_element_update`'s `render_mode`
  offset path (slide_x).

Pause/transition fades appear to be handled elsewhere (not perk selection). Capture HUD alpha when returning from perk
selection to confirm the exact fade-in timing/curve.

Perk prompt origin/bounds can be captured with `scripts/frida/perk_prompt_trace.js` (see `analysis/ghidra/maps/data_map.json`
for the underlying globals).

### Runtime capture request (next large run)

For deeper carving of `ui_menu_item_element` subtemplate blocks
(`0x0048fd78..0x004902ff`), capture:

- One memory snapshot immediately after `ui_menu_assets_init` (`0x00419dd0`)
  returns.
- One memory snapshot immediately after `ui_menu_layout_init` (`0x0044fcb0`)
  returns.
- Per-frame deltas for `0x0048fd78..0x004902ff` while visiting these states:
  main menu (`0`), options, statistics, perk selection (`6`), and in-game HUD (`9`).
- Write-trace events (address + value + EIP) for this range, especially writes to
  offsets repeating with stride `0x1c` (8-slot blocks).
- A trace of `ui_element_render` input pointers for frames where these blocks are
  visible, so we can map block/slot identity to rendered widget role.

Goal: promote block-local `_pad*` fields to named slot fields (position,
mode/timeline, UV/color tuples) with confidence across menu variants.

## UI element render (ui_element_render / FUN_00446c40)

`ui_element_render` updates focus/click handling and draws a UI element's quads,
colors, and textures. See [UI elements](../ui-elements.md) for struct details.

Keyboard focus updates are globally gated by `ui_focus_input_locked`; controls
rebind flows toggle this lock while waiting for key/axis capture.

## Main menu (state 0)

The main menu is `game_state_id == 0` and is built from the shared UI element
system (logo sign + `ui_menuItem` elements with overlay label atlas).

- [Main menu (state 0)](main-menu.md)

## Button helpers

High-confidence button helpers are tracked in
[Detangling notes](../detangling.md) under UI button helpers.
