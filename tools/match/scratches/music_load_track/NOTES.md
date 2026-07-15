# music_load_track

Increments the shared loading-progress counter, walks occupied music slots until
the first entry whose PCM and Vorbis pointers are both empty, returns `-1` as
soon as the scan reaches 128 entries, loads the requested OGG stream, logs the
failure or success path, and returns the allocated slot.

The exact VC6 `/O2 /GB` source uses an inlined free-slot helper. Its scan returns
either the first usable index or `-1`; the caller then checks that sentinel
before loading. This source shape explains the native's otherwise redundant
post-scan `result == -1` test and matches all 53 instructions and 12 references.
