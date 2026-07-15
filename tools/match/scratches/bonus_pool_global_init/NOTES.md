# `bonus_pool_global_init`

Native target: `crimsonland.exe` at `0x00412230` (23 bytes).

The CRT initializer walks the 16-entry, 0x1c-stride bonus pool and assigns
`BONUS_ID_NONE` to each entry. The other fields are already zeroed by the PE
BSS and are deliberately left untouched.
