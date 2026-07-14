# music_load_track

Increments the shared loading-progress counter, walks occupied music slots until
the first entry whose PCM and Vorbis pointers are both empty, returns `-1` as
soon as the scan reaches 128 entries, loads the requested OGG stream, logs the
failure or success path, and returns the allocated slot.

Current VC6 `/O2 /GB` result: 92.59% (53 target instructions, 55 candidate,
12 audited references). The only residual is the structured post-loop
`result == 128` exhaustion check; native branches directly from the loop bound
to its equivalent `-1` return.
