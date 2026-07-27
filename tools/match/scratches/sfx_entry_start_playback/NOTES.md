# sfx_entry_start_playback

Restores and reuploads resident PCM when needed. Streaming entries rewind,
prefill three quarters, and loop the primary buffer. Resident entries select
the first non-playing voice, falling back to a random voice and stopping it when
all 16 are busy, then apply the global playback frequency and start once.

The default VC6 `/O2 /GB` result is 77.42% with a 48.55-byte fuzzy gap
(93/93 instructions, `7/0/0` audited references). The historical Processor Pack
`/G6` experiment reached 80.21%, but it also added an instruction and cannot be
native-object provenance because the corresponding Rich records are absent.
The canonical scratch therefore keeps the evidenced default profile.

Live Binary Ninja decompilation confirms the restore/upload branch, three
stream fills, looping primary-buffer start, 16-voice status scan, random
fallback/stop, frequency update, and final non-looping start. The four
localized profile regions contain those same operations and references.
Moving `result = 0` into the resident arm, nesting it under the streaming
`else`, and spelling the streaming branch with explicit labels were probed under
stock VC6 and SP6. They regress the prefix and instruction shape, so the natural
source lifetime is retained.

Five broader mutation sweeps now record the streaming/resident lifetime, loop
shape, restore predicate, and result-reuse alternatives. The only numeric
aggregate improvement (`conditional-result-flag`, 80.00%) emits 97
instructions against the native 93 and introduces an extra reference match by
duplicating structure; the region evidence rejects it. All 93-instruction
alternatives are neutral or worse, so no source mutation is retained.

Recovery is classified `semantic-complete` with an `analysis` residual for the
unknown source shape. No volatile state, dummy dependencies, register forcing,
or artificial control flow is retained.
