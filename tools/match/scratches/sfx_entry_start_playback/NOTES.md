# sfx_entry_start_playback

Restores and reuploads resident PCM when needed. Streaming entries rewind,
prefill three quarters, and loop the primary buffer. Resident entries select
the first non-playing voice, falling back to a random voice and stopping it when
all 16 are busy, then apply the global playback frequency and start once.

The stock VC6 `/O2 /GB` result is 77.42% with a 48.55-byte fuzzy gap
(93/93 instructions, `7/0/0` audited references). A complete compiler-profile
matrix found one natural improvement: MSVC 6.5pp with
`/O2 /G6 /W3 /GR-` reaches 80.21% and reduces the gap to 42.54 bytes
(94/93 instructions, the same `7/0/0` references). The profile changes only
result-lifetime and DirectSound vtable-call scheduling; it does not change the
source.

Live Binary Ninja decompilation confirms the restore/upload branch, three
stream fills, looping primary-buffer start, 16-voice status scan, random
fallback/stop, frequency update, and final non-looping start. The four
localized profile regions contain those same operations and references.
Moving `result = 0` into the resident arm was also probed under the improved
profile and regressed to 78.92%, 92/93 instructions, and a 1/93 prefix, so the
natural source lifetime is retained.

Recovery is classified `semantic-complete` with a `compiler` residual. The
profile override records a measured 6.01-byte fuzzy improvement without
volatile state, dummy dependencies, register forcing, or artificial control
flow.
