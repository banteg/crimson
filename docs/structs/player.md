---
tags:
  - status-analysis
---

# Player struct (player_health / DAT_004908d4)

This page tracks the per-player runtime struct stored in `player_health`
(table base).

Pool facts:

- Entry size: `0x360` bytes per player (`0xd8` dwords/floats).
- Base address: `player_health` (`DAT_004908d4`).
- Access pattern: `field_base + player_index * 0x360` (disassembly often shows
  `player_index * 0xd8` because the base pointer is typed as `float*`/`u32*`).

- Input bindings (keys + axes) live in a `player_input_t` sub-struct at offset
  `0x308` (13 dwords / 0x34 bytes).

- Player 2 constants appear as base + `0x360` (e.g. `player2_health` at `DAT_00490c34`).
- Some high-confidence fields live before `player_health` (negative offsets).

## Runtime probe notes (2026-01-18)

Captured with `scripts/frida/crimsonland_probe.js` after fixing pointer-based reads.

- `player_take_damage` logs show sane values and health deltas (e.g. 100 -> 95 with `damage_f32=5`),
  confirming that the base/stride assumptions are valid for the current build.

- The unknown-field tracker flagged offsets **0x2BC / 0x2C4 / 0x2D0** as frequently changing; these
  correspond to the **alt-weapon** block already listed below (good cross-check).

- The tracker also flagged offsets **0x34C / 0x350 / 0x354** near the tail of the struct
  (observed values included `16.0` and `432.0`). These are likely real fields; add candidates below.

- The 2026-02-06 gameplay-state capture (`analysis/frida/gameplay_state_capture_summary.json`)
  confirms `player_clip_size` / `player_ammo` are float slots in memory:
  `clip_size_f32` had integer-valued floats in `1411/1411` compact snapshots and
  `ammo_f32` in `1356/1411`. This replaced the older "possible type artifact"
  assumption.

High-confidence fields (partial):

| Offset | Field | Symbol | Evidence |
| --- | --- | --- | --- |
| `-0x14` | death/respawn timer | `player_death_timer` | Decremented when health is `<= 0`; triggers game-over once below zero. |
| `-0x10` | pos_x | `player_pos_x` | Used for camera centering, distance checks, and projectile aim vectors. |
| `-0x0c` | pos_y | `player_pos_y` | Used for camera centering, distance checks, and projectile aim vectors. |
| `-0x08` | move dx | `player_move_dx` | Zeroed each tick, then filled by input movement logic. |
| `-0x04` | move dy | `player_move_dy` | Zeroed each tick, then filled by input movement logic. |
| `-0x1b` | Plaguebearer active flag | `player_plaguebearer_active` | Set when Plaguebearer is acquired; used by creature update to infect nearby monsters. |
| `0x00` | health | `player_health` | Reduced by `player_take_damage`; `<= 0` counts as dead. |
| `0x08` | body heading (radians) | `player_heading` | Used for overlays and movement vector rotation. |
| `0x10` | size / diameter | `player_size` | Halved for collision and arena bounds clamping. |
| `0x2c` | aim target x | `player_aim_x` | Used to derive aim vectors and overlay position. |
| `0x30` | aim target y | `player_aim_y` | Used to derive aim vectors and overlay position. |
| `0x38` | move speed multiplier | `player_speed_multiplier` | Multiplies movement vector (boosted by Speed bonus). |
| `0x3c` | weapon reset latch | `player_weapon_reset_latch` | Cleared by `weapon_assign_player` and `bonus_apply` (Weapon Power Up / Fire Bullets) when timers/ammo reset. |
| `0x44` | move speed / accel | `player_move_speed` | Ramps up/down based on input; scales movement. |
| `0x70` | move phase | `player_move_phase` | Incremented by movement speed, wrapped to `[0, 14]` for step/anim phase. |
| `0x78` | Hot Tempered timer | `player_hot_tempered_timer` | Used by perk ring burst logic. |
| `0x7c` | Man Bomb timer | `player_man_bomb_timer` | Charge timer for perk ring burst. |
| `0x80` | Living Fortress timer | `player_living_fortress_timer` | Accumulates while stationary. |
| `0x84` | Fire Cough timer | `player_fire_cough_timer` | Periodic Fire Cough perk timer. |
| `0x88` | experience points | `player_experience` | XP counter; drives level-ups and survival scaling. |
| `0x90` | level / perk tier | `player_level` | Increments when XP crosses thresholds; gates survival waves. |
| `0x94` | perk counts table | `player_perk_counts` | `int[0x80]` table indexed by perk id (ends at `0x294`). |
| `0x294` | spread / heat | `player_spread_heat` | Decays each frame in `player_update`; incremented by weapon spread value. |
| `0x29c` | current weapon id | `player_weapon_id` | Set by `weapon_assign_player`. |
| `0x2a0` | clip size (float slot) | `player_clip_size` | Loaded from weapon table on swap; used to reset ammo. Runtime values are integer-valued floats (for example 10.0/12.0/25.0). |
| `0x2a4` | reload active flag | `player_reload_active` | Set when a reload starts; used by Tough Reloader damage reduction. |
| `0x2a8` | current ammo (float slot) | `player_ammo` | Decrements on fire; reset when reload completes. Runtime values are integer-valued floats. |
| `0x2ac` | reload timer | `player_reload_timer` | Decremented each frame; used by reload perks. |
| `0x2b0` | shot cooldown | `player_shot_cooldown` | Decays each frame; scaled by Weapon Power Up. |
| `0x2b4` | reload timer max | `player_reload_timer_max` | Used for reload HUD progress and perk checks. |
| `0x2b8` | alt weapon id | `player_alt_weapon_id` | Saved when swapping to alt weapon (see weapon table notes). |
| `0x2bc` | alt clip size (float slot) | `player_alt_clip_size` | Saved when swapping to alt weapon. |
| `0x2c0` | alt reload active flag | `player_alt_reload_active` | Saved when swapping to alt weapon. |
| `0x2c4` | alt current ammo (float slot) | `player_alt_ammo` | Saved when swapping to alt weapon. |
| `0x2c8` | alt reload timer | `player_alt_reload_timer` | Saved when swapping to alt weapon. |
| `0x2cc` | alt shot cooldown | `player_alt_shot_cooldown` | Saved when swapping to alt weapon. |
| `0x2d0` | alt reload timer max | `player_alt_reload_timer_max` | Saved when swapping to alt weapon. |
| `0x2d8` | muzzle flash intensity | `player_muzzle_flash_alpha` | Decays each frame; accumulates on fire and drives weapon glow. |
| `0x2dc` | aim heading (radians) | `player_aim_heading` | Used for projectile direction and overlay rendering. |
| `0x2e0` | turn speed accumulator | `player_turn_speed` | Turn speed/accel when using keyboard/tank controls. |
| `0x2e4` | aux state | `player_state_aux` | Zeroed in `FUN_0041fc80` (player reset); no read sites found yet. |
| `0x2ec` | low-health timer | `player_low_health_timer` | Counts down to play low-health cues when HP is low. |
| `0x2f0` | speed bonus timer | `player_speed_bonus_timer` | Bonus id 13 (Speed). |
| `0x2f4` | shield timer | `player_shield_timer` | Bonus id 10 (Shield). |
| `0x2f8` | Fire Bullets timer | `player_fire_bullets_timer` | Bonus id 14 (Fire Bullets). |
| `0x2fc` | auto-aim target | `player_auto_target` | Stores the nearest creature index for auto-aim modes. |
| `0x300` | move target x | `player_move_target_x` | Cached target position for click/assist movement mode. |
| `0x304` | move target y | `player_move_target_y` | Cached target position for click/assist movement mode. |
| `0x308` | move key (forward) | `player_move_key_forward` | Primary movement key binding. |
| `0x30c` | move key (backward) | `player_move_key_backward` | Primary movement key binding. |
| `0x310` | turn key (left) | `player_turn_key_left` | Primary turn/rotate key binding. |
| `0x314` | turn key (right) | `player_turn_key_right` | Primary turn/rotate key binding. |
| `0x318` | fire key | `player_fire_key` | Primary fire key binding. |
| `0x31c` | keybind reserved 0 | `player_key_reserved_0` | Copied from config; no callsites yet. |
| `0x320` | keybind reserved 1 | `player_key_reserved_1` | Copied from config; no callsites yet. |
| `0x324` | aim key (left) | `player_aim_key_left` | Aim-rotate key binding. |
| `0x328` | aim key (right) | `player_aim_key_right` | Aim-rotate key binding. |
| `0x32c` | aim axis x binding | `player_axis_aim_x` | Axis binding read via input API for aim stick. |
| `0x330` | aim axis y binding | `player_axis_aim_y` | Axis binding read via input API for aim stick. |
| `0x334` | move axis x binding | `player_axis_move_x` | Axis binding read via input API for movement stick. |
| `0x338` | move axis y binding | `player_axis_move_y` | Axis binding read via input API for movement stick. |

## Candidate / unknown offsets

The runtime probe flagged offsets `0x34c/0x350/0x354` as frequently changing.
Those line up with player 2's *pre-base* fields (`player2_death_timer`,
`player2_pos_x`, `player2_pos_y`) at `player_health + 0x360 - 0x14/0x10/0x0c`, so
they are no longer considered unknown.

## Defense state (summary)

- **Health gate:** `player_health` at the table base is decremented by `player_take_damage`; `<= 0`
  counts as dead and starts `player_death_timer`.

- **Shield immunity:** when `player_shield_timer > 0`, `player_take_damage` returns early and the
  damage is ignored.

- **Reload mitigation:** `player_reload_active` is set when a reload starts; with Tough Reloader
  active, incoming damage is halved while this flag is set.

- **Low-health warning:** `player_low_health_timer` is reset when HP dips below 20 and is used to
  drive warning effects/SFX while it counts down.

## Control schemes (summary)

- Movement scheme `DAT_00480364 == 3` reads analog inputs from
  `player_axis_move_x` / `player_axis_move_y`.

- Aim scheme `DAT_0048038c == 4` reads analog inputs from
  `player_axis_aim_x` / `player_axis_aim_y`.

Related docs:

- [Gameplay glue](../crimsonland-exe/gameplay.md)
- [Weapon table](../mechanics/reference/weapon-table.md)
- [Projectile struct](projectile.md)
- [Bonus ID map](../mechanics/reference/bonus-id-map.md)
