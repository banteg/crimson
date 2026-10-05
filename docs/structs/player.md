---
tags:
  - status-analysis
---

# Player struct (player_state_table / 0x004908b0)

This page tracks the per-player runtime struct `player_state_t`
(`third_party/headers/crimsonland_types.h`), stored in
`player_state_table` (`player_state_t[2]`).

Pool facts:

- Entry size: `0x360` bytes per player (`0xd8` dwords/floats).
- Base address: `player_state_table` (`0x004908b0`).
- Access pattern: `field_base + player_index * 0x360` (disassembly often shows
  `player_index * 0xd8` because the base pointer is typed as `float*`/`u32*`).

- Input bindings (keys + axes) live in a `player_input_t` sub-struct at offset
  `0x32c` (13 dwords / `0x34` bytes), ending the entry at `0x360`.

- Player 2 fields are base + `0x360` (e.g. `player2_health` at `0x00490c34`).
- Offsets `0x00..0x97` share the entity prefix used by `creature_t`;
  `player_state_table_global_init` constructs them, but most prefix fields
  have no player reads.

Fields (offsets from `player_state_table`; `Symbol` is the player-0 data map label):

| Offset | Field | Symbol | Evidence |
| --- | --- | --- | --- |
| `0x00` | `entity_active` | — | Write-only for players: zeroed by `player_state_table_global_init` and `plugin_runtime_clear_pools`. |
| `0x04` | `entity_phase_seed` | — | Write-only for players: zeroed by `player_state_table_global_init`. |
| `0x08` | `entity_state_flag` | — | Write-only for players: zeroed by `player_state_table_global_init`. |
| `0x09` | `plaguebearer_active` | `player_plaguebearer_active` | Set when Plaguebearer is acquired; used by creature update to infect nearby monsters. |
| `0x0c` | `entity_dot_tick_timer` | — | Write-only for players: zeroed by `player_state_table_global_init`. |
| `0x10` | `death_timer` | `player_death_timer` | Decremented when health is `<= 0`; triggers game-over once below zero. |
| `0x14` | `pos_x` | `player_pos_x` | Used for camera centering, distance checks, and projectile aim vectors. |
| `0x18` | `pos_y` | `player_pos_y` | Used for camera centering, distance checks, and projectile aim vectors. |
| `0x1c` | `move_dx` | `player_move_dx` | Zeroed each tick, then filled by input movement logic. |
| `0x20` | `move_dy` | `player_move_dy` | Zeroed each tick, then filled by input movement logic. |
| `0x24` | `health` | `player_health` | Reduced by `player_take_damage`; `<= 0` counts as dead. |
| `0x28` | `max_health` | — | Entity-prefix slot; not used for players in the recovered source. |
| `0x2c` | `heading` | `player_heading` | Body heading (radians); used for overlays and movement vector rotation. |
| `0x30` | `target_heading` | — | Entity-prefix slot; not used for players in the recovered source. |
| `0x34` | `size` | `player_size` | Diameter; halved for collision and arena bounds clamping. |
| `0x38` | `entity_hit_flash_timer` | — | Write-only for players: zeroed by `player_state_table_global_init`. |
| `0x50` | `aim_x` | `player_aim_x` | Aim target; used to derive aim vectors and overlay position. |
| `0x54` | `aim_y` | `player_aim_y` | Aim target; used to derive aim vectors and overlay position. |
| `0x5c` | `speed_multiplier` | `player_speed_multiplier` | Multiplies movement vector (boosted by Speed bonus). |
| `0x60` | `weapon_reset_latch` | `player_weapon_reset_latch` | Cleared by `weapon_assign_player` and `bonus_apply` (Weapon Power Up / Fire Bullets) when timers/ammo reset. |
| `0x68` | `move_speed` | `player_move_speed` | Ramps up/down based on input; scales movement. |
| `0x74` | `entity_reserved_74` | — | Write-only for players: zeroed by `player_state_table_global_init`. |
| `0x78` | `entity_link_index` | — | Write-only for players: set to `-1` by `player_state_table_global_init`. |
| `0x90` | `entity_ai_mode` | — | Write-only for players: zeroed by `player_state_table_global_init`. |
| `0x94` | `move_phase` | `player_move_phase` | Incremented by movement speed, wrapped to `[0, 14]` for step/anim phase. |
| `0x98` | `player_reserved_98` | — | Initialized to `0.0f`; the only read compares it with `0.25f` before drawing the optional target trail. |
| `0x9c` | `hot_tempered_timer` | `player_hot_tempered_timer` | Used by perk ring burst logic. |
| `0xa0` | `man_bomb_timer` | `player_man_bomb_timer` | Charge timer for perk ring burst. |
| `0xa4` | `living_fortress_timer` | `player_living_fortress_timer` | Accumulates while stationary. |
| `0xa8` | `fire_cough_timer` | `player_fire_cough_timer` | Periodic Fire Cough perk timer. |
| `0xac` | `experience` | `player_experience` | XP counter; drives level-ups and survival scaling. |
| `0xb0` | `reset_reserved_b0` | `player_reset_reserved_b0` | Write-only: zeroed by `player_reset_all`. |
| `0xb4` | `level` | `player_level` | Increments when XP crosses thresholds; gates survival waves. |
| `0xb8` | `perk_counts` | `player_perk_counts` | `int[0x80]` table indexed by perk id (ends at `0x2b8`). |
| `0x2b8` | `spread_heat` | `player_spread_heat` | Decays each frame in `player_update`; incremented by weapon spread value. |
| `0x2c0` | `weapon_id` | `player_weapon_id` | Set by `weapon_assign_player`. |
| `0x2c4` | `clip_size` (float) | `player_clip_size` | Loaded from weapon table on swap; used to reset ammo. Holds integer values. |
| `0x2c8` | `reload_active` (byte) | `player_reload_active` | Set when a reload starts; used by Tough Reloader damage reduction. |
| `0x2cc` | `ammo` (float) | `player_ammo` | Decrements on fire; reset when reload completes. |
| `0x2d0` | `reload_timer` | `player_reload_timer` | Decremented each frame; used by reload perks. |
| `0x2d4` | `shot_cooldown` | `player_shot_cooldown` | Decays each frame; scaled by Weapon Power Up. |
| `0x2d8` | `reload_timer_max` | `player_reload_timer_max` | Used for reload HUD progress and perk checks. |
| `0x2dc` | `alt_weapon_id` | `player_alt_weapon_id` | Saved when swapping to alt weapon (see weapon table notes). |
| `0x2e0` | `alt_clip_size` (float) | `player_alt_clip_size` | Saved when swapping to alt weapon. |
| `0x2e4` | `alt_reload_active` (byte) | `player_alt_reload_active` | Saved when swapping to alt weapon. |
| `0x2e8` | `alt_ammo` (float) | `player_alt_ammo` | Saved when swapping to alt weapon. |
| `0x2ec` | `alt_reload_timer` | `player_alt_reload_timer` | Saved when swapping to alt weapon. |
| `0x2f0` | `alt_shot_cooldown` | `player_alt_shot_cooldown` | Saved when swapping to alt weapon. |
| `0x2f4` | `alt_reload_timer_max` | `player_alt_reload_timer_max` | Saved when swapping to alt weapon. |
| `0x2f8` | `reset_reserved_zero` | `player_reset_reserved_2f8` | Write-only: zeroed by `player_state_table_global_init` and `player_reset_all`. |
| `0x2fc` | `muzzle_flash_alpha` | `player_muzzle_flash_alpha` | Decays each frame; accumulates on fire and drives weapon glow. |
| `0x300` | `aim_heading` | `player_aim_heading` | Used for projectile direction and overlay rendering. |
| `0x304` | `turn_speed` | `player_turn_speed` | Turn speed/accel when using keyboard/tank controls. |
| `0x308` | `state_aux` | `player_state_aux` | Write-only: zeroed in `player_reset_all`; no reads in the recovered source. |
| `0x30c` | `evil_eyes_target_creature` | `evil_eyes_target_creature` | Evil Eyes target (player 0 only): the creature under the aim, set in `perks_update_effects`; `creature_update_all` skips its AI. `-1` when none. |
| `0x310` | `bleed_drip_timer` | `player_bleed_drip_timer` | Counts down to play low-health cues when HP is low. |
| `0x314` | `speed_bonus_timer` | `player_speed_bonus_timer` | Bonus id 13 (Speed). |
| `0x318` | `shield_timer` | `player_shield_timer` | Bonus id 10 (Shield). |
| `0x31c` | `fire_bullets_timer` | `player_fire_bullets_timer` | Bonus id 14 (Fire Bullets). |
| `0x320` | `auto_target` | `player_auto_target` | Stores the nearest creature index for auto-aim modes. |
| `0x324` | `move_target_x` | `player_move_target_x` | Cached target position for click/assist movement mode. |
| `0x328` | `move_target_y` | `player_move_target_y` | Cached target position for click/assist movement mode. |
| `0x32c` | `input.move_key_forward` | `player_move_key_forward` | Primary movement key binding. |
| `0x330` | `input.move_key_backward` | `player_move_key_backward` | Primary movement key binding. |
| `0x334` | `input.turn_key_left` | `player_turn_key_left` | Primary turn/rotate key binding. |
| `0x338` | `input.turn_key_right` | `player_turn_key_right` | Primary turn/rotate key binding. |
| `0x33c` | `input.fire_key` | `player_fire_key` | Primary fire key binding. |
| `0x340` | `input.key_reserved_0` | `player_key_reserved_0` | Write-only: copied from config; no reads in the recovered source. |
| `0x344` | `input.key_reserved_1` | `player_key_reserved_1` | Write-only: copied from config; no reads in the recovered source. |
| `0x348` | `input.aim_key_left` | `player_aim_key_left` | Aim-rotate key binding. |
| `0x34c` | `input.aim_key_right` | `player_aim_key_right` | Aim-rotate key binding. |
| `0x350` | `input.axis_aim_x` | `player_axis_aim_x` | Axis binding read via input API for aim stick. |
| `0x354` | `input.axis_aim_y` | `player_axis_aim_y` | Axis binding read via input API for aim stick. |
| `0x358` | `input.axis_move_x` | `player_axis_move_x` | Axis binding read via input API for movement stick. |
| `0x35c` | `input.axis_move_y` | `player_axis_move_y` | Axis binding read via input API for movement stick. |

Gaps (`0x3c..0x4f`, `0x58`, `0x64`, `0x6c..0x73`, `0x7c..0x8f`, `0x2bc`) are
unnamed padding in the header.

## Defense state (summary)

- **Health gate:** `health` (`0x24`, `player_health`) is decremented by `player_take_damage`; `<= 0`
  counts as dead and starts `player_death_timer`.

- **Shield immunity:** when `player_shield_timer > 0`, `player_take_damage` returns early and the
  damage is ignored.

- **Reload mitigation:** `player_reload_active` is set when a reload starts; with Tough Reloader
  active, incoming damage is halved while this flag is set.

- **Low-health warning:** accepted hits at HP `<= 20` have a 1/8 chance to reset
  `player_bleed_drip_timer`; see [player damage](../crimsonland-exe/player-damage.md).

## Control schemes (summary)

- Movement scheme `config_movement_schemes == 3` reads analog inputs from
  `player_axis_move_x` / `player_axis_move_y`.

- Aim scheme `config_aim_schemes == 4` reads analog inputs from
  `player_axis_aim_x` / `player_axis_aim_y`.

Related docs:

- [Gameplay glue](../crimsonland-exe/gameplay.md)
- [Weapon table](../re/static/reference/weapon-table.md)
- [Projectile struct](projectile.md)
- [Bonus ID map](../re/static/reference/bonus-id-map.md)
