# `particle_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e520` (159 bytes).

The CRT initializer constructs all 128 entries in the 0x38-byte particle
pool. It clears active, enables rendering, initializes the four-float scale/age
value to `(1,1,1,1)`, sets intensity to one, seeds spin from
`(rand() % 628) * 0.01f`, selects style zero, and sets target id to `-1`.

The exact VC6 source order is style id, active, intensity, the scale/age value,
spin, render flag, and target id. It produces the native induction cursor at
`particle_pool + 0x24` and confirms that style id is a byte at offset `0x30`,
not a 32-bit field; the shared native header now records that layout.
