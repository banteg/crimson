# sfx_entry_load_ogg

Reads an OGG resource into the eight-byte-prefixed memory-source format used by
the native Vorbis callbacks, opens a stack decoder, derives a 16-bit PCM format,
decodes the complete resident sample, closes the decoder, and creates 16
DirectSound voices. Native allocation, read, and short-decode failure handling
is deliberately minimal and is preserved.

The recovered source has the same 99-instruction count and all ten references
aligned, but remains an honest 97.98% WIP. The only residual is the order in
which MSVC loads `pcm_bytes` and `pcm_data` into `EDX`/`ECX` for the decode
destination; the arithmetic, call, loop, object layout, and every side effect
are otherwise identical, and the source is not contorted to force the schedule.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms the resource read, memory-source prefix,
decoder lifecycle, PCM format, complete short-decode loop, and voice creation.
Candidate and native each have 99 instructions with `10/0/0` references.
`--regions` isolates the only difference to the two equivalent decode-pointer
loads, so recovery is `semantic-complete` with a `compiler` residual.
