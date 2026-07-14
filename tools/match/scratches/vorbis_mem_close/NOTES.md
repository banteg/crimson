# vorbis_mem_close

Native target: `crimsonland.exe` at `0x0041dee0` (29 bytes).

The stream method frees its owned memory-source allocation, then clears the
embedded `OggVorbis_File`. It does not null the pointer or inspect either
return value. Natural C++ matches all 11 instructions and both references.
