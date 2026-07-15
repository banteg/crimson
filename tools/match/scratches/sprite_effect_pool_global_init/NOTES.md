# `sprite_effect_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e4a0` (97 bytes).

The CRT initializer constructs the 384 entries in the 0x2c-byte sprite-effect
pool. Each inactive entry receives an opaque-white color value; the remaining
fields retain their static zero initialization.
