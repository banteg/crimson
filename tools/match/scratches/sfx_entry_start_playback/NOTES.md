# sfx_entry_start_playback

Restores and reuploads resident PCM when needed. Streaming entries rewind,
prefill three quarters, and loop the primary buffer. Resident entries select
the first non-playing voice, falling back to a random voice and stopping it when
all 16 are busy, then apply the global playback frequency and start once.

Current VC6 `/O2 /GB` result: 77.42% (93/93 instructions, 7 audited references).
The native and candidate control flow and calls agree; the residual is register
scheduling. Initializing the result before the streaming branch makes VC6 reuse
ESI for literal zero arguments, while native initializes ESI only on entry to
the resident-voice scan. Moving it later causes VC6 to shrink-wrap the ESI save.
