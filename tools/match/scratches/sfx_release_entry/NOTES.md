# sfx_release_entry

Streaming entries close and free their Vorbis stream object, release the single
primary DirectSound buffer, and free the owned PCM backing allocation. Resident
entries release all 16 voices in reverse order before freeing PCM data. Both
paths clear released owner pointers but leave the remaining metadata intact.

Exact 52/52-instruction match with all four native references aligned.
