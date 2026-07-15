# `bonus_pool_sentinel_global_init`

Native target: `crimsonland.exe` at `0x0041f570` (11 bytes).

The CRT initializer marks the exhausted-pool sentinel as `BONUS_ID_NONE`.
Its remaining fields are already zeroed by the PE BSS.
