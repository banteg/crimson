---
tags:
  - status-draft
---

# Screens and flows

**Status:** Draft

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
- **Rewrite note:** Out of scope (storefront defunct). The rewrite keeps the
  demo loop but skips the purchase screen entirely.

## Demo trial overlay (demo_trial_overlay_render / FUN_004047c0)

- Draws the demo warning panel with remaining trial time and upgrade copy.
- Updated from the main frame loop when the demo timer is active.

## Modal/plugin flow (FUN_0040b630)

There is a modal flow keyed off state `game_state_id` (`DAT_00487270`) == `0x16` that appears to
call into a plugin interface (`plugin_interface_ptr` (`DAT_004824d4`)). This likely represents a
modal screen or external module. The exact UI and state name remain unknown.
