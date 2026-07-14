# `console_cmd_tell_time_survived`

Exact 37-byte, 9-instruction match with MSVC 6.5 `/O2 /GB`; all six masked
references align.

Live Binary Ninja shows this handler registered from `crimsonland_main`. It
converts the global millisecond counter to single-precision seconds, truncates
through VC6's `__ftol`, and prints the integer to the console log.

The explicit `float` arithmetic and native `0.00100000005f` value preserve the
observed x87 conversion without replacing it with integer division.
