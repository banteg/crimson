# vorbis_mem_seek

Native target: `crimsonland.exe` at `0x0041dd40` (66 bytes).

The memory seek callback handles `SEEK_SET`, `SEEK_END`, and a relative
fallback. End-relative movement is `size - offset`, and every path returns
`1`, including success. The high half of the 64-bit offset is intentionally
ignored. Natural C++ matches all 22 instructions with no references.
