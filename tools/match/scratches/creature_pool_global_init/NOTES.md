# `creature_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e6d0` (60 bytes).

The CRT initializer constructs 385 entries, including the pool's extra
sentinel slot. It clears the active/state/collision bytes, collision and hit
timers, phase seed, AI and animation state, plus the named
`entity_reserved_74` dword, and initializes each link index to `-1`. This
replaces the former padding cast with the same constructor-touched field shape
already recovered at offset `0x74` in `player_state_t`.

## Complete sentinel storage (2026-09-09)

The [native write-footprint proof](../../evidence/creature-pool-sentinel-2026-09-09/README.md)
confirms that the last constructed record occupies `0x004aa338..0x004aa3d0`.
The shared declaration, compiled data object, imported type, ABI size assertion,
and data-definition extent now include all 385 records. Gameplay scan bounds
remain 384. The constructor source and its normalized/reference/encoded-body
exactness are unchanged.
