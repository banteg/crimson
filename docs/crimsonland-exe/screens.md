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

## Quest results (quest_results_screen_update / FUN_00410d20)

Renders the post-mission summary and buttons:

- Final time and "Unpicked Perk Bonus" lines.
- High score entry when appropriate.
- Buttons: Play Next / Play Again / High scores / Main Menu.
- Special case for the final quest: "Show End Note".

## Quest failed screen (quest_failed_screen_update)

- Used when the player fails a quest (state `game_state_id` (`DAT_00487270`) == `0xc`).
- Renders failure text and retry options.

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
  - Set `CONFIG.forceShareware=true` to patch `game_is_full_version()` → `0` when testing the full-version binary.
  - Log output (default): `C:\\share\\frida\\demo_trial_overlay_trace.jsonl`
- Copy the JSONL log into the repo under `analysis/frida/raw/` and summarize findings in `plan.md`.

## Modal/plugin flow (FUN_0040b630)

There is a modal flow keyed off state `game_state_id` (`DAT_00487270`) == `0x16` that appears to
call into a plugin interface (`plugin_interface_ptr` (`DAT_004824d4`)). This likely represents a
modal screen or external module. The exact UI and state name remain unknown.
