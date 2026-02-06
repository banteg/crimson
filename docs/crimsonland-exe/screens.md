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

## Quest failed screen (quest_failed_screen_update)

- Used when the player fails a quest (state `game_state_id` (`DAT_00487270`) == `0xc`).
- Renders failure text and retry options.
- Note: the original string list includes a typo ("Persistence will be rewared."); we correct it to "rewarded" in the rewrite.
- `quest_failed_screen_flags` (`0x004825d8`) is the one-shot init bitfield for
  the three action buttons (Play Again / Play Another / Main Menu).

## Demo purchase screen (demo_purchase_screen_update / FUN_0040b740)

- Full-screen upsell flow.
- Renders the feature list, shows the logo/mockup, and opens the purchase URL
  when the user clicks "Purchase".

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

### Evidence capture (Windows VM)

Use Frida to log whenever the overlay is actually rendered:

- Script: `scripts\\frida\\demo_trial_overlay_trace.js`
  - Log output (default): `C:\\share\\frida\\demo_trial_overlay_trace.jsonl`
  - Note: this is expected to trigger on **demo builds** (retail may never render the overlay).
  - Optional (retail): set `CONFIG.forceDemoInGameplayLoop=true` to force the demo gate checks in `gameplay_update_and_render` (for overlay-only validation).
  - Optional (retail): set `CONFIG.forcePlaytimeMs=2400001` (with `forceDemoInGameplayLoop=true`) to trigger the “trial expired” path immediately.
  - Optional: set `CONFIG.minOverlayLogIntervalMs=250` to log at most ~4 events/sec while the overlay is visible.
- Copy the JSONL log into the repo under `analysis/frida/raw/` and summarize findings in `plan.md`.
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
