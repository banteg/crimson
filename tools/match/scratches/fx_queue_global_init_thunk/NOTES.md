# `fx_queue_global_init_thunk`

Native target: `crimsonland.exe` at `0x0041e1a0` (5 bytes).

The CRT initializer table points at this tail-call thunk, which forwards to
`fx_queue_global_init`. It is kept as a separate compiler-generated island so
both manifest functions and the initializer edge are audited.
