# Frame loop (gameplay)

**Status:** Draft

This page summarizes the main gameplay frame loop in `FUN_0040aab0` (state `9`).
Other states have their own loops but reuse the same render pass (`FUN_00405960`).

## Gating flags

- `game_paused_flag` (`DAT_004808b8`): pause toggle. When set, gameplay updates are skipped and UI
  timers are adjusted.
- `demo_mode_active` (`DAT_0048700d`): demo/attract gating. Disables HUD and alters update behavior.
- `game_state_id` (`DAT_00487270`): must be `9` for creature/projectile/player updates.
- `FUN_0041df40()`: used in multiple places to gate demo/trial timing behavior.

## Update order (simplified)

1) Time scaling: if Reflex Boost is active (`time_scale_active`), scale `DAT_00480840`
   and recompute `DAT_00480844`.
2) Perk tick helpers (`FUN_00406b40`) when not gated by demo logic.
3) `effects_update`.
4) If not paused and state is `9`:
   - `creature_update_all`
   - `projectile_update`
5) If not paused and state is `9`:
   - for each player: `player_update`
6) Mode-specific updates:
   - Survival: `survival_update`
   - Rush: `FUN_004072b0`
   - Quests: `FUN_004070e0`
7) Powerup timers and global time (`DAT_00487060`) advance when not paused.
8) Camera + shake update (`FUN_00409500`).
9) Gameplay render pass (`FUN_00405960`).
10) Tutorial timeline if `_DAT_00480360 == 8` (`tutorial_timeline_update`).
11) Perk prompt handling (`FUN_00403550`) and perk selection transition.
12) `bonus_update`.
13) HUD/UI passes:
    - `FUN_0040a510` (player indicators)
    - `FUN_0041ca90` (HUD)
    - `ui_elements_update_and_render`
14) Demo overlay and cursor handling.

Camera shake state (used by `FUN_00409500`):

- `camera_shake_offset_x` / `camera_shake_offset_y` are added to the camera center each frame.
- `camera_shake_timer` counts down between shake pulses.
- `camera_shake_pulses` is decremented as pulses complete (larger values yield stronger shakes).

## Game over transition

When all players are dead, the loop queues a state transition:

- Non-quest modes: `game_state_pending` (`DAT_00487274`) = `7`
- Quest mode: `game_state_pending` (`DAT_00487274`) = `0xc`

The transition is finalized by `ui_elements_update_and_render` when the
transition timeline completes.

## Perk selection transition

When the level-up prompt is active and the primary action is pressed, the loop
calls `perks_generate_choices()` and switches state via `FUN_004461c0(6)`.
