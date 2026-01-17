# Gameplay glue

**Status:** Draft

This page captures high-level gameplay glue that is not already covered by the
standalone data tables.

## Player update (player_update / FUN_004136b0)

`player_update` runs once per player during the main gameplay loop when
`DAT_00487270 == 9`. It handles:

- Per-player movement and aim updates.
- Weapon firing and reload timers.
- Spawning projectiles and effects tied to the active weapon.
- Applying status timers (bonus/perk effects).

### Per-player runtime fields (partial)

These are the most important per-player arrays that bridge weapons, perks, and
bonuses (stride `0xd8`, base `player_table` / `DAT_004908d4`). See
[Player struct](../player-struct.md) for offsets and related fields.

| Offset | Symbol | Meaning | Source / Notes |
| --- | --- | --- | --- |
| `0x294` | `player_spread_heat` | spread/heat | decays each frame; Sharpshooter changes decay + minimum |
| `0x29c` | `player_weapon_id` | current weapon id | set by `weapon_assign_player` |
| `0x2a0` | `player_clip_size` | clip size | from weapon table, modified by Ammo Maniac + My Favourite Weapon |
| `0x2a8` | `player_ammo` | current ammo | reset to clip size when reload completes |
| `0x2ac` | `player_reload_timer` | reload timer | decremented each frame; used by Angry/Anxious/Stationary Reloader |
| `0x2b0` | `player_shot_cooldown` | shot cooldown | decremented each frame; slowed by Weapon Power Up timer |
| `0x2b4` | `player_reload_timer_max` | reload timer max | used to compute reload progress (HUD + Angry Reloader) |
| `0x2dc` | `player_aim_heading` | aim heading (radians) | used for projectile direction + overlays |
| `0x2f0` | `player_speed_bonus_timer` | speed bonus timer | Bonus id 13 (Speed) |
| `0x2f4` | `player_shield_timer` | shield timer | Bonus id 10 (Shield) |
| `0x2f8` | `player_fire_bullets_timer` | Fire Bullets timer | Bonus id 14 (Fire Bullets) |

Alt-weapon swap caches live in the same struct (offsets `0x2b8..0x2d0`); see
[Weapon table](../weapon-table.md) for the current field map.

Global bonus timers used by `player_update` and the main loop:

| Symbol | Meaning | Source |
| --- | --- | --- |
| `_DAT_0048701c` | Weapon Power Up timer | Bonus id 4 |
| `_DAT_00487014` | Reflex Boost timer | Bonus id 9 |
| `_DAT_00487020` | Energizer timer | Bonus id 2 |
| `_DAT_00487024` | Double XP timer | Bonus id 6 |
| `_DAT_00487018` | Freeze timer | Bonus id 11 |
| `DAT_0048700e` / `_DAT_00487010` | time-scale active + factor | driven by Reflex Boost |

### Perk-triggered projectile spawns (player_update)

`player_update` owns several perk timers that spawn projectiles or FX when the
timer crosses its threshold:

- **Man Bomb** (`DAT_004c2c24`): uses `player_man_bomb_timer` (`DAT_00490950`) as a charge timer, then spawns
  8 projectiles in a ring (types `0x15/0x16`) and plays a burst SFX.
- **Fire Cough** (`DAT_004c2c2c`): uses `player_fire_cough_timer` (`DAT_00490958`) to periodically spawn a
  `0x2d` fire projectile from the muzzle and a small sprite burst.
- **Hot Tempered** (`DAT_004c2bfc`): uses `player_hot_tempered_timer` (`DAT_0049094c`) to periodically spawn a
  ring of projectiles (`0xb` and `9`).
- **Living Fortress** (`DAT_004c2c28`): increments `player_living_fortress_timer` (`DAT_00490954`) while stationary
  (clamped to ~30s); likely consumed by damage scaling elsewhere.

### Reload + spread interactions

- **Sharpshooter** (`DAT_004c2b48`) modifies how fast `DAT_00490b68` decays and
  lowers the minimum spread value.
- **Anxious Loader** (`DAT_004c2b90`) reduces the reload timer by `0.05` on each
  primary press while reloading.
- **Stationary Reloader** (`DAT_004c2c10`) triples reload decay when stationary.
- **Angry Reloader** (`DAT_004c2c20`) triggers a projectile ring (`0xb`) when the
  reload timer crosses the 50% mark.

### Regeneration tick (FUN_00406b40)

When the Regeneration perk (`DAT_004c2bb0`) is active, `FUN_00406b40` slowly
increments player health while in the main loop. This is decoupled from
`player_update` and is skipped in some demo-gated paths.

### Weapon Power Up cooldown scaling

While `_DAT_0048701c > 0` (Weapon Power Up active), `player_update` decays the
shot cooldown (`DAT_00490b84`) at 1.5x speed.

### Bonus overrides

- **Fire Bullets** (bonus id 14): while `DAT_00490bcc > 0`, `projectile_spawn`
  forces player-owned projectiles to type `0x2d` and uses the pellet count from
  the weapon table (`DAT_004d7aa0[weapon_id]`).

See the data tables for concrete values:

- [Weapon table](../weapon-table.md)
- [Projectile struct](../projectile-struct.md)
- [Effects pools](../effects-struct.md)
- [Perk ID map](../perk-id-map.md)
- [Bonus ID map](../bonus-id-map.md)

## Mode updates

Mode-specific updates are dispatched from the main frame loop:

- Survival: `survival_update` (`FUN_00407cd0`)
- Rush: `FUN_004072b0`
- Quests: `FUN_004070e0`
- Typ-o-Shooter: separate loop (`FUN_004457c0`, state `0x12`)

See [Game mode map](../game-mode-map.md) for mode ids.
