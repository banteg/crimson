# console_global_destroy

Native target: `crimsonland.exe` at `0x00401190` (10 bytes).

The ordinary global definition makes MSVC emit this finalizer: it loads
`console_log_queue` as the `this` argument and tail-calls the recovered
`console_queue_t` destructor. Selecting the compiler-generated `_$E2` helper
recovers the native shape without spelling its instructions.
