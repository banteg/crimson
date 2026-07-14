# vorbis_pcm_seek

Native target: `crimsonland.exe` at `0x0041ddb0` (22 bytes).

This `__thiscall` leaf forwards an unsigned 32-bit sample offset as a
zero-extended `ogg_int64_t` to `ov_pcm_seek(&file, offset)`. Natural C++
matches all eight instructions and the imported call reference.
