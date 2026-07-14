# console_global_init

Native target: `crimsonland.exe` at `0x00401170` (10 bytes).

The ordinary global definition makes MSVC emit this initializer: it loads
`console_log_queue` as the `this` argument and tail-calls the recovered
`console_queue_t` constructor. Selecting the compiler-generated `_$E1` helper
recovers the native shape without spelling its instructions.
