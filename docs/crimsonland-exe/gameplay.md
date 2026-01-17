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
