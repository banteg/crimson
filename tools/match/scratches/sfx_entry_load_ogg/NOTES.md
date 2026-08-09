# sfx_entry_load_ogg

Reads an OGG resource into the eight-byte-prefixed memory-source format used by
the native Vorbis callbacks, opens a stack decoder, derives a 16-bit PCM format,
decodes the complete resident sample, closes the decoder, and creates 16
DirectSound voices. Native allocation, read, and short-decode failure handling
is deliberately minimal and is preserved.

The recovered source is now exact: 99/99 instructions, a 99-instruction exact
prefix, and `10/0/0` references. The final residual was the order in which VC6
loaded the adjacent `pcm_bytes` and `pcm_data` fields for the decode
destination.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms the resource read, memory-source prefix,
decoder lifecycle, PCM format, complete short-decode loop, and voice creation.
Candidate and native each have 99 identical instructions with `10/0/0`
references, so no compiler residual remains.

## Exact aggregate-owner closure

Binary Ninja types `audio_entry_t::pcm_data` at `+0x14` immediately followed by
`pcm_bytes` at `+0x18`. Native `0x0043bde7..0x0043bdf0` loads the byte count
first, subtracts the remaining count, and then adds the data pointer. Exact
neighbor `music_stream_fill` uses the same byte-count/data-base ownership at
`0x0043c61e..0x0043c629` for its second decode attempt.

Modeling those adjacent fields as a borrowed `sfx_pcm_storage_t` subobject at
`&entry->pcm_data` preserves that natural aggregate boundary. VC6 then emits
the native `pcm_bytes`-then-`pcm_data` load order without volatile state,
forced inlining, register constraints, or changed behavior. This closes the
former 6.141414-byte weighted gap and raises 97.98% to 100% while preserving
the 99/99 instruction count and all ten references.

## Recorded decode-destination sweeps

`decode-destination-order-mutations.json` and
`decode-destination-lifetime-mutations.json` exercised expression ordering
and explicit base/offset lifetimes. A fresh audit found that the original
base/offset plan omitted the cast from the recovered `void *` PCM field, so
its supposedly complete variants had not compiled. The corrected plan
(`a341144f79f0b37486adf533ed3178053cc6dce0d093d157034da46da460b482`)
now evaluates both complete declaration/use combinations: assigning the base
first regresses to 95.96%, and assigning the offset first regresses to 94.95%.
The declaration-only form is byte-neutral; the two intentionally incomplete
use-only forms remain compile errors. No source change was retained.

`decode-destination-association-mutations.json` closes the remaining arithmetic
menu with four explicit associations, including the native-looking
`pcm_data - remaining + pcm_bytes`. VC6 canonicalizes all four byte-for-byte
to the same 99-instruction candidate, confirming that the final register-load
swap is not controlled by expression association.

`decode-destination-pointer-arithmetic-mutations.json` extends that boundary
with eight typed-pointer, signed-offset, indexing, and subtract/add spellings
under spec
`811c740f5c7b8e98ac152ad2d66934d87e33a20eee7ca648c4e63bcda04106a3`.
All eight compile byte-identically at 97.98%, 99/99 instructions, and
`10/0/0` references. The earlier one-variant authoring record is superseded by
this complete sweep.

## Inline-helper and argument-order bounds

Two recorded helper sweeps test whether an ordinary inlined source boundary
can preserve the native `pcm_bytes`-then-`pcm_data` loads. Three helper-local
lifetime forms are neutral or regress, and three parameter-order forms compile
byte-identically despite VC6's right-to-left argument evaluation. The first
inline-helper record intentionally remains as a superseded authoring failure:
the recovered `pcm_data` field is `void *`, and the corrected sweep adds the
required explicit cast. No corrected variant improves the 97.98% baseline, so
no helper is retained.
