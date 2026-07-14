# credits_line_clear_flag

Native target: `crimsonland.exe` at `0x0040d040` (66 bytes).

The wrong-click penalty walks backward from the supplied credits line until it
finds flag `0x4`, clears that bit, and plays the trooper-pain sound at full
volume. A single `while (index >= 0)` with the successful action inside the
loop reproduces the native pointer induction and negative-index exit. Natural
VC6 code matches all 20 instructions and references `5/0/0`.
