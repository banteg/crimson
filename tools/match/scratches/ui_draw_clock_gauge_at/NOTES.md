# ui_draw_clock_gauge_at

Native target: `crimsonland.exe` at `0x0040a4c0` (70 bytes).

The wrapper ignores non-positive progress, converts the supplied position to
integer coordinates, scales progress to 60,000 milliseconds, and invokes the
clock renderer at full alpha. The radius parameter is unused in the native
wrapper. Natural VC6 code matches all 22 instructions and references `6/0/0`.
