# `creature_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e6d0` (60 bytes).

The CRT initializer constructs 385 entries, including the pool's extra
sentinel slot. It clears the active/state/collision bytes, collision and hit
timers, phase seed, AI and animation state, plus the named
`entity_reserved_74` dword, and initializes each link index to `-1`. This
replaces the former padding cast with the same constructor-touched field shape
already recovered at offset `0x74` in `player_state_t`.
