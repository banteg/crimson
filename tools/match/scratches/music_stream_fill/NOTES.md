# music_stream_fill

Locks one quarter of the DirectSound ring at the decoder cursor, fills the first
lock region through the in-memory Vorbis reader, unlocks it, and advances the
cursor modulo the buffer size. The native retries one non-positive decode once,
rejects an unexpected second lock region without unlocking, and returns false on
every path; those unusual behaviors are retained.

Exact 86/86-instruction match with all four native references aligned. The
first lock length is naturally reused after `Unlock` as the cursor accumulator,
matching MSVC's original load order without introducing an artificial shim.

## 1.9.8 (C2 9044)

1.9.8 loads `stream_cursor` before the lock length when advancing the cursor.
Shared spellings tried (each exact under one compiler only): `dst1_bytes +=
cursor` (canonical), `dst1_bytes = cursor + dst1_bytes`, `cursor = (dst1_bytes
+= cursor) % size` (8966 order under both); `(cursor + dst1_bytes) % size`,
`(dst1_bytes + cursor) % size`, `cursor += dst1_bytes; cursor %= size`, a local
`int cursor` in either operand order, and reusing `remaining` (9044 order under
both). Unsigned `%` regresses both. The cursor update is therefore a
codegen-only `CL_BUILD == 10908` guard.
