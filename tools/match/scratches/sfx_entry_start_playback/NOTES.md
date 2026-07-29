# sfx_entry_start_playback

Restores and reuploads resident PCM when needed. Streaming entries rewind,
prefill three quarters, and loop the primary buffer. Resident entries select
the first non-playing voice, falling back to a random voice and stopping it when
all 16 are busy, then apply the global playback frequency and start once.

The default VC6 `/O2 /GB` result is 79.57% with a 43.92-byte fuzzy gap
(93/93 instructions, `7/0/0` audited references). The historical Processor Pack
`/G6` experiment reached 80.21%, but it also added an instruction and cannot be
native-object provenance because the corresponding Rich records are absent.
The canonical scratch therefore keeps the evidenced default profile.

Live Binary Ninja decompilation confirms the restore/upload branch, three
stream fills, looping primary-buffer start, 16-voice status scan, random
fallback/stop, frequency update, and final non-looping start. The four
localized profile regions contain those same operations and references.
Moving `result = 0` into the resident arm and nesting it under the streaming
`else` were probed under stock VC6 and SP6. They regress the prefix and
instruction shape. The later restore-to-stream CFG sweep found one useful
explicit label, described below.

Five broader mutation sweeps now record the streaming/resident lifetime, loop
shape, restore predicate, and result-reuse alternatives. The only numeric
aggregate improvement (`conditional-result-flag`, 80.00%) emits 97
instructions against the native 93 and introduces an extra reference match by
duplicating structure; the region evidence rejects it. All 93-instruction
alternatives are neutral or worse, so none of those earlier source mutations
is retained.

Recovery is classified `semantic-complete` with a `compiler` residual. No
volatile state, dummy dependencies, register forcing, or artificial control
flow is retained.

## Common-result tail sweep

Live disassembly shows the streaming arm using immediate zero arguments while
still saving `ESI` in the common prologue; the resident arm initializes `ESI`
only after the streaming test. `common-result-tail-mutations.json` tested four
single-result formulations using a common return, an explicit join, and both
branch polarities. Each emitted 92 instructions instead of the native 93 and
moved the first mismatch to the prologue; the best fell to 68.11%. The
canonical 93-instruction source therefore remains unchanged.

## Restore-to-stream CFG recovery

Live disassembly exposes one source-level edge that the earlier structured
scratch omitted. After a successful restore, a non-null stream pointer jumps
directly into the streaming body; only the upload path reloads and retests the
pointer. Adding the corresponding `stream_playback` label inside the existing
streaming branch preserves the function's semantics and all seven audited
references while raising the score from 77.42% to **79.57%**. The candidate
still has 93 instructions and a 20-instruction exact prefix. The complete
five-variant `restore-stream-cfg-mutations.json` sweep retains only that
minimal label form; moving the resident initialization or duplicating the
streaming body regresses.

The remaining placement difference is now bounded. Native saves `ESI` in the
common prologue, passes literal zeroes in the streaming arm, and initializes
`ESI` only at the resident scan. Delaying `result = 0` reproduces the latter
two choices, but both the build-8966 and build-9782 optimizers shrink-wrap the
`ESI` save into the resident arm. That 91-instruction object loses the common
prologue and falls to 73.91%. All five local declaration orders and both
branch-polarity spellings produce the same result. Six direct, indexed, named,
reference, and explicitly typed primary-buffer call forms are byte-neutral.
The recorded interaction and primary-lifetime sweeps therefore leave the
stronger 79.57% source unchanged and identify the rest as register-save and
COM-call allocation residue.
