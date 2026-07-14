# vorbis_read_pcm16

Native target: `crimsonland.exe` at `0x0041df00` (55 bytes).

The method calls `ov_read` for signed, little-endian 16-bit PCM using the
embedded bitstream index. Zero returns immediately; a negative result is
clamped to zero while a positive result is preserved. Keeping the explicit
zero fast path reproduces the native branchless sign mask. Natural C++ matches
all 22 instructions and the imported call reference.
