# music_stream_fill

Locks one quarter of the DirectSound ring at the decoder cursor, fills the first
lock region through the in-memory Vorbis reader, unlocks it, and advances the
cursor modulo the buffer size. The native retries one non-positive decode once,
rejects an unexpected second lock region without unlocking, and returns false on
every path; those unusual behaviors are retained.

Exact 86/86-instruction match with all four native references aligned. The
first lock length is naturally reused after `Unlock` as the cursor accumulator,
matching MSVC's original load order without introducing an artificial shim.
