# config_ensure_file

Native target: `crimsonland.exe` at `0x0041f130` (112 bytes).

The recovered bootstrap opens `crimson.cfg` through `game_build_path`. An
existing file is closed immediately; when absent, violence is disabled in the
default configuration and the complete `0x480`-byte config blob is written to
a new binary file. Passing the nested path-builder result directly to `fopen`
recovers the native right-to-left argument evaluation and stack cleanup.

Natural VC6 code matches all 36 instructions and references `13/0/0`.
