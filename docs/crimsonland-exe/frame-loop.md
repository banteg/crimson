---
tags:
  - status-analysis
---

# Frame loop (gameplay)
This page summarizes the main gameplay frame loop in `gameplay_update_and_render` (state `9`).
Other states have their own loops but reuse the same render pass (`gameplay_render_world`, `0x00405960`).

## Gating flags

- `game_paused_flag` (`0x004808b8`): pause toggle. When set, gameplay updates are skipped and UI
  timers are adjusted.

- `demo_mode_active` (`0x0048700d`): demo/attract gating. Disables HUD and alters update behavior.
- `game_state_id` (`0x00487270`): must be `9` for creature/projectile/player updates.
- `game_is_full_version()`: used in multiple places to gate demo/trial timing behavior.

## Update order (simplified)

1) Time scaling: if Reflex Boost is active (`time_scale_active`), scale `frame_dt`
   and recompute `frame_dt_ms`.

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
7) Powerup timers and global time (`survival_elapsed_ms`) advance when not paused.
8) Camera + shake update (`camera_update`).
9) Gameplay render pass (`gameplay_render_world`, `0x00405960`).
10) Tutorial timeline if `config_game_mode == 8` (`tutorial_timeline_update`).
11) Perk prompt handling (`perk_prompt_update_and_render`, `0x00403550`) and perk selection transition.
    - `perk_prompt_timer` (`0x0048f524`) ramps 0..200 when perks are pending; it feeds the prompt
      alpha and transform matrix (`perk_prompt_transform_*` at `perk_prompt_transform_cos..perk_prompt_transform_cos_2`).
    - `perk_prompt_hover_active` (`0x0048f500`) + `perk_prompt_pulse` (`0x0048f504`) drive the
      hover/pulse feedback and click gating.
    - `perk_prompt_origin_x/y` (`0x0048f224`/`perk_prompt_origin_y`) with bounds
      (`perk_prompt_bounds_min_*` at `perk_prompt_bounds_min_x/0048f24c`, `perk_prompt_bounds_max_*` at
      `perk_prompt_bounds_max_x/0048f284`) define the perk prompt hover rectangle.
    - `perk_choices_dirty` (`0x00486fb0`) forces a one-shot `perks_generate_choices()` before
      switching to state `6`.

12) `bonus_update`.
13) HUD/UI passes:
    - `ui_render_aim_indicators` (player indicators)
    - `hud_update_and_render` (HUD)
    - `ui_elements_update_and_render`

14) Demo overlay and cursor handling.
    - `ui_analog_cursor_active` (`0x004808c8`) enables stick-driven cursor movement in non-gameplay states.
    - Screenshot capture key path uses `screenshot_file_index` (`0x004808c4`) and
      `screenshot_filename_buf` (`0x0047f634`) to probe `shot_XX.bmp` filenames.

Camera shake state (used by `camera_update`):

- `camera_shake_offset_x` / `camera_shake_offset_y` are added to the camera center each frame.
- `camera_shake_timer` counts down between shake pulses.
- `camera_shake_pulses` is decremented as pulses complete (larger values yield stronger shakes).

## Game over transition

When all players are dead, the loop queues a state transition:

- Non-quest modes: `game_state_pending` (`0x00487274`) = `7`
- Quest mode: `game_state_pending` (`0x00487274`) = `0xc`

The transition is finalized by `ui_elements_update_and_render` when the
transition timeline completes.

## Perk selection transition

When the level-up prompt is active and the primary action is pressed, the loop
calls `perks_generate_choices()` and switches state via `game_state_set` (`0x004461c0(6)`).
