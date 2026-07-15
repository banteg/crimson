# `player_state_table_global_init_thunk`

Native target: `crimsonland.exe` at `0x0041e5c0` (5 bytes).

The CRT initializer table points at this tail-call thunk, which forwards to
`player_state_table_global_init`.
