# `unused_global_noop_init`

Native target: `crimsonland.exe` at `0x0041e0c0` (1 byte).

The CRT chain retains this empty constructor body. It accepts no object
pointer, writes no data, and has no callers beyond its tail thunk, so the
underlying unused global cannot be named more specifically from evidence.
