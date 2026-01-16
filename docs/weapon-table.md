# Weapon table (FUN_004519b0)

**Status:** In progress

Weapon stats are initialized in `FUN_004519b0` and stored in a fixed‑stride
table. The accessor `FUN_0041fc60(weapon_id)` returns:

```
&DAT_004d7a2c + weapon_id * 0x1f
```

`0x1f` is a count of `u32` slots, so the stride is **0x7c bytes** per entry.
Entry `0` is a dummy (id = -1); weapon id `0` (Pistol) starts at entry `1`.

## Offsets (relative to entry base)

All offsets below are in **bytes**, relative to the pointer returned by
`FUN_0041fc60`.

| Offset | Type  | Meaning | Evidence |
| ------ | ----- | ------- | -------- |
| `0x48` | float | Fire rate (seconds per shot) | Set per‑weapon alongside reload/spread in `FUN_004519b0`. (No direct symbolized read; inferred as the remaining rate field.) |
| `0x4c` | float | Reload time | Loaded into `DAT_00490b80` in `FUN_00413430`. |
| `0x50` | float | Spread / recoil increment | Added to `DAT_00490bac` after each shot in `FUN_00444980`. |
| `0x6c` | int   | Projectile type | Used in `FUN_00420440` when spawning a projectile. |
| `0x70` | float | Damage multiplier | Used in hit resolution around `FUN_00415095` (damage formula uses `DAT_004d7a9c`). |

## Notes

- The table also stores clip size, ammo type, sounds, UI icon id, and flags.
  Those can be mapped later if needed.
- Many fields are only written in `FUN_004519b0`; only a subset are referenced
  by symbol elsewhere (reload/spread/projectile/damage).
