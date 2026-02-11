---
tags:
  - status-analysis
---

# Screens and flows
This page groups full-screen or modal flows that have their own update loops.

## Game over / high score entry (game_over_screen_update)

- Used for non-quest modes (state `game_state_id` (`DAT_00487270`) == `7`).
- Handles high score entry, shows stats, and routes back to menu.
- Plays exclusive SFX on entry when `game_state_pending` (`DAT_00487274`) == `0x19` and transition flag
  `ui_transition_direction` (`DAT_0048724c`) is set.
- Uses `game_over_name_input_buffer` (`0x0048256c`) as the editable player-name
  buffer for `ui_text_input_update`.
- Companion text-input state globals:
  `game_over_name_input_state` (`0x00482590`),
  `game_over_name_input_state_max_chars` (`0x00482598`),
  `game_over_name_input_state_width_px` (`0x0048259c`), and
  `game_over_name_input_state_alpha` (`0x004825a0`).
- `game_over_highscore_rank_index` (`0x004825a4`) stores
  `highscore_rank_index()` for the current score; values `>= 100` skip top-100
  name entry.
- `game_over_name_input_initial_length` (`0x00482594`) caches the original
  active-record name length so final copy-back/termination preserves expected
  bounds.
- Uses `highscore_card_text_buffer` (`0x004d0da0`) as a shared scratch buffer
  for score/time/rank text in `ui_text_input_render`.
- Action button structs are persistent globals:
  `game_over_play_again_button` (`0x00482508`),
  `game_over_highscores_button` (`0x00482550`),
  `game_over_main_menu_button` (`0x00482538`), and
  `game_over_name_submit_button` (`0x004825a8`).

## Quest results (quest_results_screen_update / FUN_00410d20)

Renders the post-mission summary and buttons:

- Final time and "Unpicked Perk Bonus" lines.
- High score entry when appropriate.
- Buttons: Play Next / Play Again / High scores / Main Menu.
- Special case for the final quest: "Show End Note".

Recovered staged-reveal globals:

- `quest_results_final_time_ms` (`DAT_0048270c`) is computed as
  `quest_spawn_timeline + perk_pending_count * -1000 - quest_results_health_bonus_ms`.
- `quest_results_reveal_base_time_ms` (`DAT_00482710`) animates up to `quest_spawn_timeline`.
- `quest_results_reveal_health_bonus_ms` (`DAT_00482714`) animates up to
  `quest_results_health_bonus_ms` (displayed as a subtraction).
- `quest_results_reveal_perk_bonus_s` (`DAT_00482718`) animates per-second bonus count from
  `perk_pending_count`.
- `quest_results_reveal_total_time_ms` (`DAT_00482720`) is the running total shown on the final line.
- `quest_results_reveal_step_timer_ms` (`DAT_00482724`) drives reveal pacing (`700`, `40`, `150`,
  `300`, `1000`, `50` ms windows).
- `quest_results_unlock_weapon_id` / `quest_results_unlock_perk_id`
  (`DAT_00482700` / `DAT_00482704`) gate the unlock text rows.
- Name entry uses `quest_results_name_input_buffer` (`0x004825dc`) as the
  temporary UI text-input storage before writing `highscore_active_record`.
- Companion text-input state globals:
  `quest_results_name_input_state` (`0x004826e8`),
  `quest_results_name_input_state_max_chars` (`0x004826f0`),
  `quest_results_name_input_state_width_px` (`0x004826f4`), and
  `quest_results_name_input_state_alpha` (`0x004826f8`).
- `quest_results_highscore_rank_index` (`0x00482620`) stores
  `highscore_rank_index()` and gates whether top-100 name entry is shown.
- `quest_results_name_input_initial_length` (`0x004826ec`) caches the original
  active-record name length for final copy-back/termination.
- Persistent action button structs:
  `quest_results_play_next_button` (`0x004825c0`),
  `quest_results_play_again_button` (`0x00482608`),
  `quest_results_highscores_button` (`0x00482668`),
  `quest_results_main_menu_button` (`0x004826b0`), and
  `quest_results_name_submit_button` (`0x00482520`) for the name-entry "Ok"
  path.

## Quest failed screen (quest_failed_screen_update)

- Used when the player fails a quest (state `game_state_id` (`DAT_00487270`) == `0xc`).
- Renders failure text and retry options.
- Note: the original string list includes a typo ("Persistence will be rewared."); we correct it to "rewarded" in the rewrite.
- `quest_failed_screen_flags` (`0x004825d8`) is the one-shot init bitfield for
  the three action buttons (Play Again / Play Another / Main Menu).
- Persistent action button structs:
  `quest_failed_play_again_button` (`0x00482680`),
  `quest_failed_play_another_button` (`0x00482698`), and
  `quest_failed_main_menu_button` (`0x004824f0`).
- `quest_failed_highscore_rank_index` (`0x00482604`) snapshots
  `highscore_rank_index()` on entry for top-100 flow gating.

## Game completed screen (game_update_victory_screen / FUN_00406350)

- Post-completion routing screen that offers mode shortcuts and a return to main
  menu.
- Uses `game_completed_screen_flags` (`0x00480321`) as one-shot init guards for
  navigation button setup.
- Persistent navigation button globals:
  `game_completed_survival_button` (`0x0047f5e0`),
  `game_completed_rush_button` (`0x00480280`),
  `game_completed_typo_button` (`0x00480328`), and
  `game_completed_main_menu_button` (`0x00480268`).

## Database screens (unlocked weapons/perks)

- `unlocked_weapons_nav_focus_index` (`0x004d1200`) and
  `unlocked_perks_nav_focus_index` (`0x004d1204`) track keyboard focus between
  the Back button (`0`) and list area (`1`) for left/right navigation.

## Highscore screen action routing

- `highscore_screen_action_id` (`0x004d1214`) carries the active click/confirm
  target in `highscore_screen_update`:
  - `-3` / `-2`: quest stage left/right arrows.
  - positive values: action buttons (sync, play, back).
- When entering highscores from game-over/quest-result flows, return context is
  snapshotted in:
  `highscore_return_game_mode_id` (`0x00487258`),
  `highscore_return_quest_stage_major` (`0x00487250`),
  `highscore_return_quest_stage_minor` (`0x00487254`), and
  `highscore_return_hardcore_flag` (`0x0048725c`).

## Credits screen (credits_screen_update)

- `credits_line_max_index` (`0x004811b8`) tracks the highest initialized line
  in `credits_line_table`.
- `credits_scroll_time_s` (`0x004811c0`) accumulates `frame_dt` and drives
  scrolling.
- `credits_scroll_line_start_index` / `credits_scroll_line_end_index`
  (`0x00481184` / `0x00481180`) define the visible line window each frame.

## Demo purchase screen (demo_purchase_screen_update / FUN_0040b740)

- Full-screen upsell flow.
- Renders the feature list, shows the logo/mockup, and opens the purchase URL
  when the user clicks "Purchase".
- Persistent action-button globals:
  `demo_purchase_purchase_button` (`0x0047f678`) and
  `demo_purchase_maybe_later_button` (`0x004802b0`).
- Browser launch uses `shell_execute_operation_open` (`0x00471b38`) as the
  `ShellExecuteA` operation string (`"open"`).

- **Rewrite note:** implemented in the Python rewrite for parity (the purchase
  URL is legacy).

## Demo trial overlay (demo_trial_overlay_render / FUN_004047c0)

- Draws the demo warning panel with remaining trial time and upgrade copy.
- Updated from the main frame loop when the demo timer is active.
- Key globals (v1.9.93):
  - Global trial timer (ms): `game_status_blob.game_sequence_id` (`0x00485794`)
  - Quest-only grace timer (ms): `demo_trial_elapsed_ms` (`0x0048084c`)
  - Mode id: `config_game_mode` (`0x00480360`) (`1=survival`, `2=rush`, `3=quest`, `8=tutorial`)
  - Quest stage gating: `quest_stage_major`/`quest_stage_minor` (`0x00487004`/`0x00487008`)
  - Action buttons: `demo_trial_purchase_button` (`0x0047f5f8`),
    `ui_button_maybe_later` (`0x00480808`), and
    `ui_button_already_paid` (`0x0047f610`).

### Evidence capture (Windows VM)

Use Frida to log whenever the overlay is actually rendered:

- Script: `scripts\\frida\\demo_trial_overlay_trace.js`
  - Log output (default): `C:\\share\\frida\\demo_trial_overlay_trace.jsonl`
  - Note: this is expected to trigger on **demo builds** (retail may never render the overlay).
  - Optional (retail): set `CONFIG.forceDemoInGameplayLoop=true` to force the demo gate checks in `gameplay_update_and_render` (for overlay-only validation).
  - Optional (retail): set `CONFIG.forcePlaytimeMs=2400001` (with `forceDemoInGameplayLoop=true`) to trigger the “trial expired” path immediately.
  - Optional: set `CONFIG.minOverlayLogIntervalMs=250` to log at most ~4 events/sec while the overlay is visible.
- Copy the JSONL log into the repo under `analysis/frida/raw/` and summarize findings in your session notes.
- Optional: validate the log against the Python model:
  - `uv run scripts/demo_trial_overlay_validate.py analysis/frida/raw/demo_trial_overlay_trace.jsonl`

## Mods / plugin runtime (plugin_runtime_update_and_render)

- State `0x14` is the mods browser/menu flow (launch list + fallback target).
  The state callback in `game_state_set` is `mods_menu_update`.
- State `0x16` is the active plugin runtime flow driven by `plugin_interface_ptr`
  (`DAT_004824d4`).
- `plugin_runtime_update_and_render` owns the frame dispatch for `0x16` and
  routes back to `0x14` when the plugin exits or is unavailable.
- Runtime latches: `plugin_runtime_needs_init` gates one-shot plugin `Init()`,
  and `plugin_runtime_active_latch` preserves resume-to-plugin behavior through pause/menu callbacks.
