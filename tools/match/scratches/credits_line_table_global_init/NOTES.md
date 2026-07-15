# `credits_line_table_global_init`

Native target: `crimsonland.exe` at `0x0040cfe0` (24 bytes).

The CRT initializer clears both the owned text pointer and flags of every
record in the 256-entry credits-line table. The native store order is flags,
then text, over the natural eight-byte record stride.
