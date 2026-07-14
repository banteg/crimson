# music_load_track

Increments the shared loading-progress counter, takes the first music slot whose
PCM and Vorbis pointers are both empty, loads the requested OGG stream, logs the
result, and returns the allocated slot. Exhaustion returns `-1`.

Current VC6 `/O2 /GB` result: 92.59% (53 target instructions, 55 candidate,
10 audited references and 2 branch-swapped string references). The remaining
delta is a redundant post-loop `result == 128` check and the equivalent
success/failure logging branch orientation; all slot, load, log, counter, and
return behavior is recovered.
