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
- Profile name text-input state in `ui_profile_menu_update`:
  `profile_name_input_state` (`0x004d0f28`),
  `profile_name_input_state_cursor` (`0x004d0f2c`),
  `profile_name_input_state_max_chars` (`0x004d0f30`),
  `profile_name_input_state_width_px` (`0x004d0f34`),
  `profile_name_input_state_alpha` (`0x004d0f38`).
- `credits_screen_init_flags` (`0x00480978`): `credits_screen_update` one-shot
  setup guards for Back and Secret buttons.
- `mods_menu_init_flags` (`0x00481bb8`): `mods_menu_update` one-shot setup
  guards for list widget and action buttons.
- `unlocked_weapons_database_init_flags` (`0x004ccc51`): one-shot setup guards
  for the unlocked-weapons database list and Back button.
- `unlocked_perks_database_init_flags` (`0x004ccc50`): one-shot setup guards
  for the unlocked-perks database list and Back button.
- `quest_select_screen_flags` (`0x004d79d4`): `quest_select_menu_update`
  runtime setup guards for Hardcore checkbox and Back button.
- `demo_trial_overlay_init_flags` (`0x0047f62c`): `demo_trial_overlay_render`
  one-shot setup guards for Maybe later / Purchase / Already paid.
- `demo_trial_purchase_button` (`0x0047f5f8`):
  persistent `ui_button_t` state used by `demo_trial_overlay_render` for the
  Purchase action.
- `tutorial_prompt_dialog_init_flags` (`0x00480148`):
  `tutorial_prompt_dialog` one-shot setup guards for Repeat / Play buttons.
- `tutorial_prompt_repeat_button` (`0x00480250`) and
  `tutorial_prompt_primary_button` (`0x004807d0`):
  persistent `ui_button_t` states used by `tutorial_prompt_dialog` (primary
  label switches between "Play a game" and "Skip tutorial").
- `demo_purchase_screen_init_flags` (`0x00480320`):
  `demo_purchase_screen_update` one-shot setup guards for Maybe later /
  Purchase.
- `ui_aim_indicators_init_flags` (`0x00480340`):
  `ui_render_aim_indicators` one-shot atexit registration guards.
- `ui_hud_init_flags` (`0x0048f528`):
  `ui_render_hud` one-shot setup guard for quest-progress bar tint defaults.

Additional shared UI strings/globals:

- `menu_label_back` (`0x00472e80`): shared `"Back"` label used by multiple
  menu buttons.
- `s_fmt_decimal_int` / `s_fmt_decimal_int_zero_prefixed`
  (`0x00471f40` / `0x00471f44`): `%d` and `0%d` format strings used in menu
  counters and demo-time formatting.
- `screen_height_f` (`0x00471144`): float mirror of `_config_screen_height` used
  by centered splash/loading layout.
- `stats_menu_easter_egg_roll` (`0x00471308`): one-shot random roll (`0..31`)
  used by `statistics_menu_update` for the March-3 "Orbes Volantes Exstare"
  Easter-egg text gate (`roll == 3`, then reset to `-1`).
- `ui_button_tex_small` / `ui_button_tex_medium`
  (`0x00478670` / `0x00478674`): lazy-loaded texture-handle caches used by
  `ui_button_update` for small/medium button frames.
- `ui_menu_item_color_idle_*` (`0x004ccd40..0x004ccd4c`) and
  `ui_menu_item_color_hover_*` (`0x004d0e28..0x004d0e34`): persistent RGBA
  palette vectors used by `ui_menu_item_update` for idle/hover text tint.

## Quest HUD helper globals

Recovered runtime globals used by the in-game quest panel in `ui_render_hud`:

- `quest_progress_bar_color_r/g/b/a` (`0x004871a0..0x004871ac`):
  RGBA vector passed to `ui_draw_progress_bar` for quest-kill progress fill.
  RGB is seeded to `(0.2, 0.8, 0.3)` and alpha is scaled from transition alpha.
- `quest_stage_label_buffer` (`0x0048f788`):
  scratch text buffer used for formatted stage labels (`major-minor`) near the
  quest title card.

## Controls menu lists

Recovered controls-menu dropdown blocks (`ui_list_widget_t`, size `0x1c`):

- `controls_move_method_list` (`0x004d7638`)
- `controls_aim_method_list` (`0x004d76a8`)
- `controls_player_profile_list` (`0x004d7660`)

`controls_menu_update` recomputes `.enabled` each frame so only one dropdown
stays interactive while the others are open.

## Options sliders

Recovered segmented-slider state blocks used by `options_menu_update`
(`ui_segmented_slider_update`):

- SFX volume: `options_sfx_volume_slider` (`0x004d77f8`)
- Music volume: `options_music_volume_slider` (`0x004d75e8`)
- Graphics detail preset: `options_graphics_detail_slider` (`0x004d7590`)
- Mouse sensitivity: `options_mouse_sensitivity_slider` (`0x004d7680`)
- Checkbox state blocks (`ui_checkbox_t`):
  `options_ui_info_checkbox` (`0x004d77e0`),
  `controls_direction_arrow_checkbox` (`0x004d77f0`),
  `quest_select_hardcore_checkbox` (`0x004d7700`),
  `highscore_hardcore_checkbox` (`0x004d0d98`), and
  `highscore_online_scores_checkbox` (`0x004d0e20`).

Additional controls-rebind runtime globals:

- `ui_menu_item_t` (`0x10` bytes, `ui_menu_item_update` payload):
  `label` (+0x0), `hovered` (+0x4), `activated` (+0x5), `enabled` (+0x6),
  `hover_phase` (+0x8), `alpha` (+0xc).
- `ui_list_widget_t` (`0x1c` bytes, `ui_list_widget_update` payload):
  `enabled` (+0x0), `open` (+0x4), `selected_index` (+0x8), `items` (+0xc),
  `item_count` (+0x10), `hovered` (+0x14), `active_index` (+0x18).
- Rebind action table passed to `ui_menu_item_update`:
  `controls_rebind_items` (`0x004d7898`, `controls_rebind_item_table_t`)
  with slot aliases such as `controls_rebind_move_secondary_item`,
  `controls_rebind_move_tertiary_item`, `controls_rebind_move_quaternary_item`,
  `controls_rebind_fire_item`, `controls_rebind_torso_left_item`,
  `controls_rebind_torso_right_item`,
  `controls_rebind_aim_up_down_axis_item`,
  `controls_rebind_aim_left_right_axis_item`,
  `controls_rebind_move_up_down_axis_item`,
  `controls_rebind_move_left_right_axis_item` (`0x004d78a8..0x004d7958`).
- `controls_key_pick_perk_item` (`0x004d7968`): `ui_menu_item_t` slot for
  the Level Up action; `.label` is updated from `_config_key_pick_perk`.
- `controls_key_reload_item` (`0x004d7978`): `ui_menu_item_t` slot for the
  Reload/Move-to-cursor action; `.label` is updated from `_config_key_reload`.
- `controls_rebind_axis_peak_abs_13f/140/141/153/154/155`
  (`0x004d79e4..0x004d79f8`): per-axis absolute-value peaks accumulated during
  analog rebind capture and compared against the `0.5` assignment threshold.

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

Recovered action-button globals for this state:

- `perk_selection_cancel_button` (`0x00480090`)
- `perk_selection_select_button` (`0x00480820`)
- Choice-item state table base:
  `perk_selection_choice_items` (`0x004800a8`,
  `perk_selection_choice_item_table_t`) with stride `0x10` across perk slots.
- Perk-selection one-shot idle/hover color vectors:
  `perk_selection_choice_color_idle_*` (`0x00480298..0x004802a4`) and
  `perk_selection_choice_color_hover_*` (`0x00480310..0x0048031c`).

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
- `main_menu_full_version_layout_latch` (`0x00486faa`) is a one-shot guard
  used by main-menu layout update paths to avoid reapplying full-version slot
  shifts every frame.

## Button helpers

High-confidence button helpers are tracked in
[Detangling notes](../detangling.md) under UI button helpers.
