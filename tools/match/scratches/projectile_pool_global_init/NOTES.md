# `projectile_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e760` (51 bytes).

The CRT initializer constructs all 96 entries in the 0x40-byte projectile
pool. Each entry starts inactive with owner `-1`, pistol type, unit speed and
travel scales, and zero hit radius.
