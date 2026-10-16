# music_entry_load_ogg

Reads an OGG resource into the native memory-source prefix, allocates a retained
Vorbis decoder, derives a 16-bit PCM format, and allocates a zeroed two-second
ring. It creates one globally focused DirectSound buffer with volume, pan, and
the corrected-position cursor flag, then clears pending refill progress. Native
failure paths leave allocations owned by the partially initialized entry.

Exact 125/125-instruction match with all 13 native references aligned. Keeping
the retained decoder only in the entry, rather than duplicating it in a local,
reproduces MSVC's native `ESI`/`EDI` allocation and clarifies the ownership.

## 1.9.8 (C2 9044)

Exact through translation-unit context: 9044 reuses what it learned compiling
earlier functions of the unit, so the resource reader that precedes this
function in 1.9.8 (`resource_open_read`, or `resource_read_alloc` for the WAV
loader) lets the size or entry stay in a callee-saved register across the
calls. The guarded copy of that body is the same mechanism as
`projectile_update`'s; 1.9.93 (8966) is unaffected.
