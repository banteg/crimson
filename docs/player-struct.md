# Player struct (player_table / DAT_004908d4)

This page tracks the per-player runtime struct stored in `player_table`.

Pool facts:

- Entry size: `0xd8` bytes per player.
- Base address: `player_table` (`DAT_004908d4`).
- Access pattern: `field_base + player_index * 0xd8`.

High-confidence fields (partial):

| Offset | Field | Symbol | Evidence |
| --- | --- | --- | --- |
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
