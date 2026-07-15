# `particle_pool_global_init_thunk`

Native target: `crimsonland.exe` at `0x0041e510` (5 bytes).

The CRT initializer table points at this tail-call thunk, which forwards to
`particle_pool_global_init`.
