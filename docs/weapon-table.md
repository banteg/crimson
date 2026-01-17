# Weapon table (weapon_table_init)

**Status:** In progress

Weapon stats are initialized in `weapon_table_init` (`FUN_004519b0`) and stored
in a fixed‑stride table. The accessor `weapon_table_entry` (`FUN_0041fc60`)
returns a pointer to the name buffer at the start of each entry:

```
&DAT_004d7a2c + weapon_id * 0x1f
```

`0x1f` is a count of `u32` slots, so the stride is **0x7c bytes** per entry.
Entry `0` is a dummy (id = -1); weapon id `0` (Pistol) starts at entry `1`.

Note: the returned pointer is **not** the first field of the entry.
There is a 4‑byte field at offset `-0x04` that is indexed with the same stride.

## Offsets (relative to entry base)

All offsets below are in **bytes**, relative to the pointer returned by
`FUN_0041fc60`.

| Offset | Type  | Meaning | Evidence |
| ------ | ----- | ------- | -------- |
| `-0x04` | int | Ammo class / HUD indicator | Used to choose `ui_ui_ind*` icons in the HUD: `0=bullet`, `1=fire`, `2=rocket`, else electric. |
| `0x00` | char[0x40] | Weapon name | String is copied inline during `weapon_table_init` and rendered in the HUD weapon list via `FUN_0041c4b0`. |
| `0x40` | byte | Unlocked/available flag | `FUN_00452e40` clears the table then marks unlocked weapons; `FUN_00452cd0` skips entries with `0`. |
| `0x44` | int | Clip size | Copied from `DAT_004d7a70` into `DAT_00490b74` on weapon swap and used to reset `DAT_00490b7c`. |
| `0x48` | float | Shot cooldown | Copied into `DAT_00490b84` after firing in `FUN_00444980`. |
| `0x4c` | float | Reload time | Loaded into `DAT_00490b80` in `FUN_00413430` (scaled by perks). |
| `0x50` | float | Spread / heat increment | Added to `DAT_00490b68` after each shot (scaled by perks). |
| `0x58` | int | Shot SFX base id | Used with `0x5c` to pick a random fire SFX. |
| `0x5c` | int | Shot SFX variant count | `rand % count + base` in `FUN_00444980`. |
| `0x60` | int | Reload / equip SFX id | Played when a reload starts and when swapping to the weapon. |
| `0x64` | int | HUD icon id | Passed into the HUD sprite selection (shifted by `<< 1`). |
| `0x68` | byte | Flags | Bit `0x1` triggers a muzzle flash / effect burst; bits `0x4/0x8` affect crosshair rendering. |
| `0x6c` | float | Projectile meta value | Copied into projectile entries on spawn; no direct reads yet. |
| `0x70` | float | Damage scale | Used in projectile hit damage computation (`DAT_004d7a9c`). |
| `0x74` | int | Pellet count | Number of pellets spawned in the spread fire path. |

## Notes

- Ammo class values (offset `-0x04`): `0` bullet (`ui_ui_indBullet.jaz`), `1` fire
  (`ui_ui_indFire.jaz`), `2` rocket (`ui_ui_indRocket.jaz`), `>= 3` electric
  (`ui_ui_indElectric.jaz`).
- Flag bits (offset `0x68`): `0x1` spawn muzzle flash / shot burst effect
  (`FUN_0042e120(0x12, ...)`), `0x4` use the smaller crosshair size, `0x8` hide
  the crosshair entirely.
- The alt-weapon swap stores per-player runtime state in parallel arrays:
  `DAT_00490b8c` (weapon id), `DAT_00490b90` (clip size), `DAT_00490b98`
  (current ammo), `DAT_00490b9c` (reload timer), `DAT_00490ba0` (shot cooldown),
  and `DAT_00490ba4` (reload timer max).
- The same stride is used by projectile metadata lookups (`DAT_004d7a98`,
  `DAT_004d7a9c`) keyed by projectile type ids in `projectile_spawn` and
  `projectile_update`.
- Many fields are only written in `FUN_004519b0`; only a subset are referenced
  by symbol elsewhere (reload/spread/sfx/flags/damage).
