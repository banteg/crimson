# `game_status_global_init_thunk`

Native target: `crimsonland.exe` at `0x00412290` (5 bytes).

The CRT initializer table points at this tail-call thunk, which forwards to
`game_status_global_init`. It is kept as a separate compiler-generated island
so both manifest functions and the initializer edge are audited.
