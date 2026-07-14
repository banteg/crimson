# vorbis_mem_close_callback

Native target: `crimsonland.exe` at `0x0041dd90` (6 bytes).

The `ov_callbacks` close hook ignores its datasource and returns `1`; the
stream object retains ownership. Natural C++ matches both instructions.
