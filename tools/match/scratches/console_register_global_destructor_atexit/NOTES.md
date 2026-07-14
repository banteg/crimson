# console_register_global_destructor_atexit

Native target: `crimsonland.exe` at `0x00401180` (12 bytes).

This `void` helper registers `console_global_destroy` with the static CRT. The
callback at `0x00401190` loads `console_log_queue` as `this` and tail-calls the
recovered queue destructor; it is not the independently callable clear-log
command previously named in the map.

The source matches all four instructions, full prefix, with the callback and
`crt_atexit` references aligned. Its discarded call result explains the native
single-register stack pop.
