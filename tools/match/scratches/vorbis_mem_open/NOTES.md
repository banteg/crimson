# vorbis_mem_open

Native target: `crimsonland.exe` at `0x0041ddd0` (260 bytes).

The C++ `vorbis_stream_t::open` method installs all four memory callbacks,
initializes the owned `[size, cursor, bytes...]` allocation, and opens its
inline bytes through `ov_open_callbacks`. It copies the complete 32-byte
`vorbis_info`, calculates decoded PCM bytes as
`ov_pcm_total * channels * 16 / 8`, and records the cursor left after header
parsing. A negative open result prints the native diagnostic and returns false.

Repeated access through the `memory_source` member, rather than keeping a local
source pointer, reproduces the native reload and callback-copy schedule.
Natural C++ matches all 91 instructions and all 13 references under MSVC 6.5.
