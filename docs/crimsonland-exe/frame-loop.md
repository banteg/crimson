---
tags:
  - status-draft
---

# Frame loop (gameplay)

**Status:** Draft

This page summarizes the main gameplay frame loop in `gameplay_update_and_render` (state `9`).
Other states have their own loops but reuse the same render pass (`gameplay_render_world`, `FUN_00405960`).

## Gating flags

- `game_paused_flag` (`DAT_004808b8`): pause toggle. When set, gameplay updates are skipped and UI
  timers are adjusted.

- `demo_mode_active` (`DAT_0048700d`): demo/attract gating. Disables HUD and alters update behavior.
- `game_state_id` (`DAT_00487270`): must be `9` for creature/projectile/player updates.
- `game_is_full_version()`: used in multiple places to gate demo/trial timing behavior.

## Update order (simplified)

1) Time scaling: if Reflex Boost is active (`time_scale_active`), scale `DAT_00480840`
   and recompute `DAT_00480844`.

2) Perk tick helpers (`perks_update_effects`) when not gated by demo logic.
3) `effects_update`.
4) If not paused and state is `9`:
   - `creature_update_all`
   - `projectile_update`
5) If not paused and state is `9`:
   - for each player: `player_update`
6) Mode-specific updates:
   - Survival: `survival_update`
   - Rush: `rush_mode_update`
   - Quests: `quest_mode_update`
7) Powerup timers and global time (`DAT_00487060`) advance when not paused.
8) Camera + shake update (`camera_update`).
9) Gameplay render pass (`gameplay_render_world`, `FUN_00405960`).
10) Tutorial timeline if `_DAT_00480360 == 8` (`tutorial_timeline_update`).
11) Perk prompt handling (`perk_prompt_update_and_render`, `FUN_00403550`) and perk selection transition.
    - `perk_prompt_timer` (`DAT_0048f524`) ramps 0..200 when perks are pending; it feeds the prompt
      alpha and transform matrix (`perk_prompt_transform_*` at `DAT_0048f510..DAT_0048f51c`).
    - `perk_prompt_hover_active` (`DAT_0048f500`) + `perk_prompt_pulse` (`DAT_0048f504`) drive the
      hover/pulse feedback and click gating.
    - `perk_prompt_origin_x/y` (`DAT_0048f224`/`DAT_0048f228`) with bounds
      (`perk_prompt_bounds_min_*` at `DAT_0048f248/0048f24c`, `perk_prompt_bounds_max_*` at
      `DAT_0048f280/0048f284`) define the perk prompt hover rectangle.
    - `perk_choices_dirty` (`DAT_00486fb0`) forces a one-shot `perks_generate_choices()` before
      switching to state `6`.

12) `bonus_update`.
13) HUD/UI passes:
    - `ui_render_aim_indicators` (player indicators)
    - `hud_update_and_render` (HUD)
    - `ui_elements_update_and_render`

14) Demo overlay and cursor handling.

Camera shake state (used by `camera_update`):

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
calls `perks_generate_choices()` and switches state via `game_state_set` (`FUN_004461c0(6)`).
