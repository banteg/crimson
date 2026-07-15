# `creature_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e6d0` (60 bytes).

The CRT initializer constructs 385 entries, including the pool's extra
sentinel slot. It clears the active/state/collision bytes, collision and hit
timers, phase seed, AI and animation state, plus the reserved word at offset
`0x74`, and initializes each link index to `-1`.
