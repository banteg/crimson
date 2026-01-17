# Player struct (player_table / DAT_004908d4)

This page tracks the per-player runtime struct stored in `player_table`.

Pool facts:

- Entry size: `0xd8` bytes per player.
- Base address: `player_table` (`DAT_004908d4`).
- Access pattern: `field_base + player_index * 0xd8`.
- Some high-confidence fields live before `player_table` (negative offsets).

High-confidence fields (partial):

| Offset | Field | Symbol | Evidence |
| --- | --- | --- | --- |
| `-0x10` | pos_x | `player_pos_x` | Used for camera centering, distance checks, and projectile aim vectors. |
| `-0x0c` | pos_y | `player_pos_y` | Used for camera centering, distance checks, and projectile aim vectors. |
| `-0x08` | move dx | `player_move_dx` | Zeroed each tick, then filled by input movement logic. |
| `-0x04` | move dy | `player_move_dy` | Zeroed each tick, then filled by input movement logic. |
| `0x08` | body heading (radians) | `player_heading` | Used for overlays and movement vector rotation. |
| `0x10` | size / diameter | `player_size` | Halved for collision and arena bounds clamping. |
| `0x2c` | aim target x | `player_aim_x` | Used to derive aim vectors and overlay position. |
| `0x30` | aim target y | `player_aim_y` | Used to derive aim vectors and overlay position. |
| `0x38` | move speed multiplier | `player_speed_multiplier` | Multiplies movement vector (boosted by Speed bonus). |
| `0x44` | move speed / accel | `player_move_speed` | Ramps up/down based on input; scales movement. |
| `0x78` | Hot Tempered timer | `player_hot_tempered_timer` | Used by perk ring burst logic. |
| `0x7c` | Man Bomb timer | `player_man_bomb_timer` | Charge timer for perk ring burst. |
| `0x80` | Living Fortress timer | `player_living_fortress_timer` | Accumulates while stationary. |
| `0x84` | Fire Cough timer | `player_fire_cough_timer` | Periodic Fire Cough perk timer. |
| `0x294` | spread / heat | `player_spread_heat` | Decays each frame in `player_update`; incremented by weapon spread value. |
| `0x29c` | current weapon id | `player_weapon_id` | Set by `weapon_assign_player`. |
| `0x2a0` | clip size | `player_clip_size` | Loaded from weapon table on swap; used to reset ammo. |
| `0x2a8` | current ammo | `player_ammo` | Decrements on fire; reset when reload completes. |
| `0x2ac` | reload timer | `player_reload_timer` | Decremented each frame; used by reload perks. |
| `0x2b0` | shot cooldown | `player_shot_cooldown` | Decays each frame; scaled by Weapon Power Up. |
| `0x2b4` | reload timer max | `player_reload_timer_max` | Used for reload HUD progress and perk checks. |
| `0x2b8` | alt weapon id | `player_alt_weapon_id` | Saved when swapping to alt weapon (see weapon table notes). |
| `0x2bc` | alt clip size | `player_alt_clip_size` | Saved when swapping to alt weapon. |
| `0x2c4` | alt current ammo | `player_alt_ammo` | Saved when swapping to alt weapon. |
| `0x2c8` | alt reload timer | `player_alt_reload_timer` | Saved when swapping to alt weapon. |
| `0x2cc` | alt shot cooldown | `player_alt_shot_cooldown` | Saved when swapping to alt weapon. |
| `0x2d0` | alt reload timer max | `player_alt_reload_timer_max` | Saved when swapping to alt weapon. |
| `0x2dc` | aim heading (radians) | `player_aim_heading` | Used for projectile direction and overlay rendering. |
| `0x2f0` | speed bonus timer | `player_speed_bonus_timer` | Bonus id 13 (Speed). |
| `0x2f4` | shield timer | `player_shield_timer` | Bonus id 10 (Shield). |
| `0x2f8` | Fire Bullets timer | `player_fire_bullets_timer` | Bonus id 14 (Fire Bullets). |

Related docs:

- [Gameplay glue](crimsonland-exe/gameplay.md)
- [Weapon table](weapon-table.md)
- [Projectile struct](projectile-struct.md)
- [Bonus ID map](bonus-id-map.md)
