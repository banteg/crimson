# `projectile_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e760` (51 bytes).

The CRT initializer constructs all 96 entries in the 0x40-byte projectile
pool. Each entry starts inactive with owner `-1`, pistol type, unit speed and
travel scales, and zero hit radius.

Because this loop owns a record-base cursor, its fields now use the flat
semantic `projectile_t::fields` view. The nested position/velocity cursor view
is reserved for code that actually indexes from an interior member. This type
recovery is byte-neutral and retains the exact 16/16 instructions and 1/0/0
reference audit.
