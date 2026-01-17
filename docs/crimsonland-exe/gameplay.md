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
bonuses (stride `0xd8`):

| Symbol | Meaning | Source / Notes |
| --- | --- | --- |
| `DAT_00490b70` | current weapon id | set by `weapon_assign_player` |
| `DAT_00490b74` | clip size | from weapon table, modified by Ammo Maniac + My Favourite Weapon |
| `DAT_00490b7c` | current ammo | reset to clip size when reload completes |
| `DAT_00490b80` | reload timer | decremented each frame; used by Angry/Anxious/Stationary Reloader |
| `DAT_00490b84` | shot cooldown | decremented each frame; slowed by Weapon Power Up timer |
| `DAT_00490b88` | reload timer max | used to compute reload progress (HUD + Angry Reloader) |
| `DAT_00490b68` | spread/heat | decays each frame; Sharpshooter changes decay + minimum |
| `DAT_00490bb0` | aim heading (radians) | used for projectile direction + overlays |
| `DAT_00490bc4` | speed bonus timer | Bonus id 13 (Speed) |
| `DAT_00490bc8` | shield timer | Bonus id 10 (Shield) |
| `DAT_00490bcc` | Fire Bullets timer | Bonus id 14 (Fire Bullets) |

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

- **Man Bomb** (`DAT_004c2c24`): uses `DAT_00490950` as a charge timer, then spawns
  8 projectiles in a ring (types `0x15/0x16`) and plays a burst SFX.
- **Fire Cough** (`DAT_004c2c2c`): uses `DAT_00490958` to periodically spawn a
  `0x2d` fire projectile from the muzzle and a small sprite burst.
- **Hot Tempered** (`DAT_004c2bfc`): uses `DAT_0049094c` to periodically spawn a
  ring of projectiles (`0xb` and `9`).
- **Living Fortress** (`DAT_004c2c28`): increments `DAT_00490954` while stationary
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
