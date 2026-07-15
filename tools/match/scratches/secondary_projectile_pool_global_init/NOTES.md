# `secondary_projectile_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e460` (41 bytes).

The CRT initializer constructs all 64 entries in the 0x2c-byte secondary
projectile pool. Each entry starts inactive with rocket type, zero life and
trail timers, and the still-unresolved tail sentinel at offset `0x28` set to
`-100`. The sentinel keeps its reserved name until a runtime use establishes
its semantics.
