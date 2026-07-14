# music_entry_load_ogg

Reads an OGG resource into the native memory-source prefix, allocates a retained
Vorbis decoder, derives a 16-bit PCM format, and allocates a zeroed two-second
ring. It creates one globally focused DirectSound buffer with volume, pan, and
the corrected-position cursor flag, then clears pending refill progress. Native
failure paths leave allocations owned by the partially initialized entry.

Exact 125/125-instruction match with all 13 native references aligned. Keeping
the retained decoder only in the entry, rather than duplicating it in a local,
reproduces MSVC's native `ESI`/`EDI` allocation and clarifies the ownership.
