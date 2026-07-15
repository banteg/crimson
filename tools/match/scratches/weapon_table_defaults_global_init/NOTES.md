# `weapon_table_defaults_global_init`

Native target: `crimsonland.exe` at `0x00451910` (150 bytes).

The CRT initializer constructs all 64 native weapon rows before the larger
weapon metadata initializer applies per-weapon overrides. Every row starts
with the display name `Unknown`, zero ammo class, locked state, empty clip,
one-second shot and reload timings, zero spread, one shot-SFX variant, icon
zero, flags zero, 45 units of travel budget, and unit damage scale.

The local construction view includes the hidden ammo-class word immediately
before the public weapon table row and records the native 0x7c-byte stride.
Fields not written here are already zeroed by the PE BSS.

Defining the rows as a real C++ global array reproduces the compiler-generated
initializer exactly, including VC6's induction pointer at `damage_scale` and
the inlined `strcpy` schedule. This is stronger source-shape evidence than a
handwritten loop with the same assignments.
